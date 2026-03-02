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

	fn encode_cells_le(values: &[B128]) -> Vec<u8> {
		let mut out = Vec::with_capacity(values.len() * 16);
		for value in values {
			out.extend_from_slice(&value.val().to_le_bytes());
		}
		out
	}

	#[test]
	fn end_to_end_commit_prove_verify_small() -> Result<(), FriBiniusError> {
		let data = patterned_data(1024); // 1 KiB

		let cfg = FriParamsConfig {
			log_inv_rate: 1,
			num_test_queries: 32,
			arity: 2,
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
			arity: 2,
			log_num_shares: 8,
			n_vars: 0,
		};

		let mut rng = StdRng::from_seed([1u8; 32]);
		let (pcs, ctx, packed, commit_output, _commitment) = commit_bytes(cfg, &data)?;

		let eval_point = pcs.sample_evaluation_point(&mut rng);
		let eval_claim = pcs.calculate_evaluation_claim(&packed.packed_values, &eval_point)?;

		let (terminate_codeword, query_prover, proof) = pcs.prove_with_openings::<B128>(
			packed.packed_mle.clone(),
			&ctx,
			&commit_output,
			&eval_point,
		)?;
		let bundle = pcs.build_eval_proof_bundle(&proof, &terminate_codeword, &query_prover, 0)?;
		pcs.verify_eval_proof_bundle(&bundle, eval_claim, &eval_point, &ctx)?;

		Ok(())
	}

	#[test]
	fn end_to_end_verify_with_extra_query_openings() -> Result<(), FriBiniusError> {
		use binius_verifier::config::B128;

		let data = patterned_data(16 * 1024);

		let cfg = FriParamsConfig {
			log_inv_rate: 1,
			num_test_queries: 128,
			arity: 2,
			log_num_shares: 8,
			n_vars: 0,
		};

		let mut rng = StdRng::from_seed([11u8; 32]);
		let (pcs, ctx, packed, commit_output, _commitment) = commit_bytes(cfg, &data)?;

		let eval_point = pcs.sample_evaluation_point(&mut rng);
		let eval_claim = pcs.calculate_evaluation_claim(&packed.packed_values, &eval_point)?;

		let (terminate_codeword, query_prover, proof) = pcs.prove_with_openings::<B128>(
			packed.packed_mle.clone(),
			&ctx,
			&commit_output,
			&eval_point,
		)?;

		let layers = query_prover
			.vcs_optimal_layers()
			.map_err(|e| FriBiniusError::Proof(e.to_string()))?;
		let terminate_codeword_vec = terminate_codeword.iter_scalars().collect::<Vec<_>>();

		let mut extra_transcript = pcs.open(0, &query_prover)?;

		pcs.verify_with_extra_query(
			&proof,
			eval_claim,
			&eval_point,
			&ctx,
			0,
			&terminate_codeword_vec,
			&layers,
			&mut extra_transcript,
		)?;

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
			arity: 2,
			log_num_shares: 8,
			n_vars: 0,
		};

		let mut rng = StdRng::from_seed([2u8; 32]);

		let (pcs, ctx, _packed, commit_output, commitment) = commit_bytes(cfg, &data)?;

		let log_batch_size = ctx.fri_params.log_batch_size();
		let leaf_count = 1usize
			<< (ctx
				.fri_params
				.rs_code()
				.log_len()
				.saturating_sub(log_batch_size));
		assert!(leaf_count > 0);

		let num_samples = usize::min(10, leaf_count);
		let mut proofs = Vec::with_capacity(num_samples);

		for _ in 0..num_samples {
			let idx = rng.random_range(0..leaf_count);
			let opened_values = commit_output
				.codeword
				.to_ref()
				.chunk(log_batch_size, idx)
				.iter_scalars()
				.collect::<Vec<_>>();

			let transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;

			proofs.push(SamplingProof::new(
				idx as u32,
				encode_cells_le(&opened_values),
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
		let v = FriParamsVersion::V0;
		let n_vars = 17;
		let cfg = v.to_config(n_vars);

		assert_eq!(cfg.log_inv_rate, 1);
		assert_eq!(cfg.num_test_queries, 128);
		assert_eq!(cfg.arity, 2);
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
			arity: 2,
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
			let log_batch_size = blob.ctx.fri_params.log_batch_size();
			let leaf_count = 1usize
				<< (blob
					.ctx
					.fri_params
					.rs_code()
					.log_len()
					.saturating_sub(log_batch_size));
			assert!(leaf_count > 0, "blob {blob_idx} has empty codeword");

			// randomly sampling 10 cells per blob, same as current lc
			let samples = usize::min(10, leaf_count);
			let mut sampled_indices = Vec::with_capacity(samples);

			// Sample distinct indices at random
			while sampled_indices.len() < samples {
				let idx = rng.random_range(0..leaf_count);
				if !sampled_indices.contains(&idx) {
					sampled_indices.push(idx);
				}
			}

			for &idx in &sampled_indices {
				// Node side: provide (value, inclusion proof) for this index
				let sampled_values = blob
					.commit_output
					.codeword
					.to_ref()
					.chunk(log_batch_size, idx)
					.iter_scalars()
					.collect::<Vec<_>>();
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
					&sampled_values,
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
			arity: 2,
			log_num_shares: 8,
			n_vars: 0,
		};

		let mut rng = StdRng::seed_from_u64(99);

		let (pcs, ctx, _packed, commit_output, commitment) = commit_bytes(cfg, &data)?;

		let log_batch_size = ctx.fri_params.log_batch_size();
		let leaf_count = 1usize
			<< (ctx
				.fri_params
				.rs_code()
				.log_len()
				.saturating_sub(log_batch_size));
		assert!(leaf_count > 0);

		// Pick a random index to test
		let idx = rng.random_range(0..leaf_count);

		let honest_values = commit_output
			.codeword
			.to_ref()
			.chunk(log_batch_size, idx)
			.iter_scalars()
			.collect::<Vec<_>>();

		// Honest proof should verify
		{
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;
			pcs.verify_inclusion_proof(&mut transcript, &honest_values, idx, &ctx, &commitment)?;
		}

		// Corrupted value should fail
		{
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;
			let mut bad_values = honest_values.clone();
			bad_values[0] += B128::from(1u128);

			let res =
				pcs.verify_inclusion_proof(&mut transcript, &bad_values, idx, &ctx, &commitment);

			assert!(res.is_err(), "verification should fail for corrupted value");
		}

		// Corrupted commitment should fail
		{
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;

			let mut bad_commitment = commitment.clone();
			bad_commitment.digest[0] ^= 0x42; // flip a byte

			let res = pcs.verify_inclusion_proof(
				&mut transcript,
				&honest_values,
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

		let params_version = FriParamsVersion::V0;
		let cfg = params_version.to_config(n_vars);

		let pcs = FriBiniusPCS::new(cfg);
		let ctx = pcs
			.initialize_fri_context::<B128>(packed.packed_mle.log_len())
			.expect("initialize_fri_context must succeed");

		let commit_output = pcs
			.commit(&packed.packed_mle, &ctx)
			.expect("commit must succeed");

		// Turn Merkle root into H256 for header storage
		let commitment_bytes = commit_output.commitment.to_vec();

		// In the real node, data_root would be merkle root of raw blobs;
		// here we just fake one for testing.
		let data_root = H256::repeat_byte(0xAB);

		let blob_meta = FriBlobCommitment {
			// random blob_hash, insignificant here
			blob_hash: data_root,
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

		assert_eq!(inner.params_version, FriParamsVersion::V0);
		assert_eq!(inner.blobs.len(), 1);
		assert_eq!(inner.blobs[0].size_bytes, blob_size as u64);
		assert_eq!(inner.blobs[0].commitment, commitment_bytes);

		let mut rng = StdRng::from_seed([7u8; 32]);
		let eval_point = pcs.sample_evaluation_point(&mut rng);
		let eval_claim = pcs
			.calculate_evaluation_claim(&packed.packed_values, &eval_point)
			.expect("claim must succeed");

		let (terminate_codeword, query_prover, proof) = pcs
			.prove_with_openings::<B128>(
				packed.packed_mle.clone(),
				&ctx,
				&commit_output,
				&eval_point,
			)
			.expect("prove_with_openings must succeed");
		let bundle = pcs
			.build_eval_proof_bundle(&proof, &terminate_codeword, &query_prover, 0)
			.expect("build_eval_proof_bundle must succeed");

		pcs.verify_eval_proof_bundle(&bundle, eval_claim, &eval_point, &ctx)
			.expect("Fri evaluation proof bundle must verify");
	}
}
