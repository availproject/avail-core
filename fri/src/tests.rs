#[cfg(test)]
mod e2e_tests {
	use crate::core::{FriCommitOutput, SamplingProof};
	pub use crate::encoding::BytesEncoder;
	use crate::{e2e_helpers::*, transcript_to_bytes, FriBiniusPCS, FriCommitment, FriContext};
	use crate::{FriBiniusError, FriParamsConfig};
	use avail_core::header::extension::{
		fri::FriHeader,
		fri_v1::{FriBlobCommitment, HeaderExtension as FriV1HeaderExtension},
		HeaderExtension as CoreHeaderExtension,
	};
	use avail_core::FriParamsVersion;
	use binius_verifier::config::B128;
	use codec::{Decode, Encode};
	use primitive_types::H256;
	use rand::{rngs::StdRng, Rng, SeedableRng};

	fn patterned_data(size: usize) -> Vec<u8> {
		(0..size).map(|i| (i % 256) as u8).collect()
	}

	#[test]
	fn end_to_end_commit_prove_verify_small() -> Result<(), FriBiniusError> {
		let data = patterned_data(1024); // 1 KiB

		let cfg = FriParamsConfig {
			log_inv_rate: 1,
			num_test_queries: 32,
			log_num_shares: 8,
			n_vars: 0, // will be filled from data
		};

		let mut rng = StdRng::from_seed([0u8; 32]);

		commit_prove_verify_bytes(cfg, &data, &mut rng)
	}

	#[test]
	fn end_to_end_commit_and_manual_prove_verify() -> Result<(), FriBiniusError> {
		use binius_verifier::config::B128;

		let data = patterned_data(16 * 1024); // 16 KiB

		let cfg = FriParamsConfig {
			log_inv_rate: 1,
			num_test_queries: 128,
			log_num_shares: 8,
			n_vars: 0,
		};

		let mut rng = StdRng::from_seed([1u8; 32]);
		let (pcs, ctx, packed, commit_output, _commitment) = commit_bytes(cfg, &data)?;

		let eval_point = pcs.sample_evaluation_point(&mut rng);
		let eval_claim = pcs.calculate_evaluation_claim(&packed.packed_values, &eval_point)?;

		let proof =
			pcs.prove::<B128>(packed.packed_mle.clone(), &ctx, &commit_output, &eval_point)?;

		// Verify using the explicit claim + evaluation point
		pcs.verify(&proof, eval_claim, &eval_point, &ctx)?;

		Ok(())
	}

	#[test]
	fn end_to_end_inclusion_proofs() -> Result<(), FriBiniusError> {
		use binius_verifier::config::B128;
		use rand::{Rng, SeedableRng};

		let data = patterned_data(8 * 1024);

		let cfg = FriParamsConfig {
			log_inv_rate: 1,
			num_test_queries: 64,
			log_num_shares: 8,
			n_vars: 0,
		};

		let mut rng = StdRng::from_seed([2u8; 32]);

		let (pcs, ctx, _packed, commit_output, commitment) = commit_bytes(cfg, &data)?;

		let codeword_len = commit_output.codeword.len();
		assert!(codeword_len > 0);

		let num_samples = usize::min(10, codeword_len);
		let mut proofs = Vec::with_capacity(num_samples);

		for _ in 0..num_samples {
			let idx = rng.random_range(0..codeword_len);
			let value = commit_output.codeword[idx];

			let transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;

			proofs.push(SamplingProof::new(
				idx as u32,
				value.val().to_le_bytes().to_vec(),
				transcript_to_bytes(&transcript),
			));
		}

		for proof in &proofs {
			proof.verify_b128(&pcs, &ctx, &commitment)?;
		}

		Ok(())
	}

	#[test]
	fn fri_params_version_zero_maps_to_expected_config() {
		let v = FriParamsVersion(0);
		let n_vars = 17;
		let cfg = v.to_config(n_vars);

		assert_eq!(cfg.log_inv_rate, 1);
		assert_eq!(cfg.num_test_queries, 128);
		assert_eq!(cfg.log_num_shares, 80);
		assert_eq!(cfg.n_vars, n_vars);
	}

	#[test]
	fn multiple_blobs_da_sampling_succeeds() -> Result<(), FriBiniusError> {
		// Simulate a block with multiple blobs of different sizes
		let blob_sizes = [1024usize, 8 * 1024, 64 * 1024]; // 1KB, 8KB, 64KB

		// Base FRI config; n_vars will be filled per-blob based on data size
		let base_cfg = FriParamsConfig {
			log_inv_rate: 1,
			num_test_queries: 64,
			log_num_shares: 8,
			n_vars: 0,
		};

		let mut rng = StdRng::seed_from_u64(42);

		// Block producer side: compute commitments for each blob
		struct BlobState {
			#[allow(dead_code)]
			data: Vec<u8>, // original blob bytes (node-only)
			pcs: FriBiniusPCS, // PCS instance (could be shared across blobs in future)
			ctx: FriContext,   // FRI context for this blob (depends on length)
			commit_output: FriCommitOutput<B128>, // full commit output (codeword + merkle)
			commitment: FriCommitment, // what goes into the header
		}

		let mut blobs = Vec::new();

		for &size in &blob_sizes {
			let data = patterned_data(size);
			let cfg = base_cfg; // copy the base config

			let (pcs, ctx, _packed, commit_output, commitment) = commit_bytes(cfg, &data)?;

			blobs.push(BlobState {
				data,
				pcs,
				ctx,
				commit_output,
				commitment,
			});
		}

		// Light client side:
		// - sees the per-blob commitments + blob sizes (Either from the header or from SummaryTxPostInherent)
		// - wants to randomly sample cells in each blob's codeword
		//   and verify Merkle inclusion proofs.

		for (blob_idx, blob) in blobs.iter().enumerate() {
			let codeword_len = blob.commit_output.codeword.len();
			assert!(codeword_len > 0, "blob {blob_idx} has empty codeword");

			// randomly sampling 10 cells per blob, same as current lc
			let samples = usize::min(10, codeword_len);
			let mut sampled_indices = Vec::with_capacity(samples);

			// Sample distinct indices at random
			while sampled_indices.len() < samples {
				let idx = rng.random_range(0..codeword_len);
				if !sampled_indices.contains(&idx) {
					sampled_indices.push(idx);
				}
			}

			for &idx in &sampled_indices {
				// Node side: provide (value, inclusion proof) for this index
				let value = blob.commit_output.codeword[idx];
				let mut proof_transcript = blob
					.pcs
					.inclusion_proof::<B128>(&blob.commit_output.committed, idx)?;

				// Light client side: verify inclusion using only:
				// - value
				// - index
				// - commitment from header
				// - per-blob FRI context (which it can reconstruct from size + config)
				blob.pcs.verify_inclusion_proof(
					&mut proof_transcript,
					&[value],
					idx,
					&blob.ctx,
					&blob.commitment,
				)?;
			}
		}

		Ok(())
	}

	#[test]
	fn da_sampling_detects_corrupted_data_and_commitment() -> Result<(), FriBiniusError> {
		let data = patterned_data(16 * 1024); // 16KB
		let cfg = FriParamsConfig {
			log_inv_rate: 1,
			num_test_queries: 64,
			log_num_shares: 8,
			n_vars: 0,
		};

		let mut rng = StdRng::seed_from_u64(99);

		let (pcs, ctx, _packed, commit_output, commitment) = commit_bytes(cfg, &data)?;

		let codeword_len = commit_output.codeword.len();
		assert!(codeword_len > 0);

		// Pick a random index to test
		let idx = rng.random_range(0..codeword_len);

		let honest_value = commit_output.codeword[idx];

		// Honest proof should verify
		{
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;
			pcs.verify_inclusion_proof(&mut transcript, &[honest_value], idx, &ctx, &commitment)?;
		}

		// Corrupted value should fail
		{
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;
			let mut bad_value = honest_value;
			// change the original value
			bad_value += B128::from(1u128);

			let res =
				pcs.verify_inclusion_proof(&mut transcript, &[bad_value], idx, &ctx, &commitment);

			assert!(res.is_err(), "verification should fail for corrupted value");
		}

		// Corrupted commitment should fail
		{
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;

			let mut bad_commitment = commitment.clone();
			bad_commitment.digest[0] ^= 0x42; // flip a byte

			let res = pcs.verify_inclusion_proof(
				&mut transcript,
				&[honest_value],
				idx,
				&ctx,
				&bad_commitment,
			);

			assert!(
				res.is_err(),
				"verification should fail for corrupted commitment"
			);
		}

		Ok(())
	}

	#[test]
	fn fri_header_drives_fri_pcs_end_to_end() {
		let blob_size = 1024 * 1024; // 1 MiB
		let blob_bytes: Vec<u8> = (0..blob_size).map(|i| (i % 251) as u8).collect();

		let packed = BytesEncoder::<B128>::new()
			.bytes_to_packed_mle(&blob_bytes)
			.expect("bytes_to_packed_mle must succeed");
		let n_vars = packed.total_n_vars;

		let params_version = FriParamsVersion(0);
		let cfg = params_version.to_config(n_vars);

		let pcs = FriBiniusPCS::new(cfg);
		let ctx = pcs
			.initialize_fri_context::<B128>(packed.packed_mle.log_len())
			.expect("initialize_fri_context must succeed");

		let commit_output = pcs
			.commit(&packed.packed_mle, &ctx)
			.expect("commit must succeed");

		// Turn Merkle root into H256 for header storage
		let commitment_bytes = commit_output.commitment.clone();

		// In the real node, data_root would be merkle root of raw blobs;
		// here we just fake one for testing.
		let data_root = H256::repeat_byte(0xAB);

		let blob_meta = FriBlobCommitment {
			size_bytes: blob_size as u64,
			commitment: commitment_bytes.clone(),
		};

		let fri_v1_header = FriV1HeaderExtension {
			blobs: vec![blob_meta.clone()],
			data_root,
			params_version,
		};

		// Wrap in versioned FriHeader + top-level HeaderExtension
		let core_header = CoreHeaderExtension::Fri(FriHeader::V1(fri_v1_header.clone()));

		let encoded = core_header.encode();
		let decoded =
			CoreHeaderExtension::decode(&mut &encoded[..]).expect("SCALE decode must succeed");

		assert!(decoded.is_fri());
		assert_eq!(decoded.data_root(), data_root);

		// Extract inner Fri v1 header again
		let inner = match decoded {
			CoreHeaderExtension::Fri(FriHeader::V1(h)) => h,
			_ => panic!("expected Fri V1 header"),
		};

		assert_eq!(inner.params_version.0, 0);
		assert_eq!(inner.blobs.len(), 1);
		assert_eq!(inner.blobs[0].size_bytes, blob_size as u64);
		assert_eq!(inner.blobs[0].commitment, commitment_bytes);

		let mut rng = StdRng::from_seed([7u8; 32]);
		let eval_point = pcs.sample_evaluation_point(&mut rng);
		let eval_claim = pcs
			.calculate_evaluation_claim(&packed.packed_values, &eval_point)
			.expect("claim must succeed");

		let proof = pcs
			.prove::<B128>(packed.packed_mle.clone(), &ctx, &commit_output, &eval_point)
			.expect("prove must succeed");

		pcs.verify(&proof, eval_claim, &eval_point, &ctx)
			.expect("Fri evaluation proof must verify");
	}
}
