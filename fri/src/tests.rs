#[cfg(test)]
mod e2e_tests {
	use crate::core::FriCommitOutput;
	use crate::{e2e_helpers::*, FriBiniusPCS, FriCommitment, FriContext};
	use crate::{FriBiniusError, FriParamsConfig};
	use binius_verifier::config::B128;
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
			n_vars: 0, // auto-filled from data
		};

		let mut rng = StdRng::from_seed([1u8; 32]);

		// --- 1. Commit from bytes ---
		let (pcs, ctx, packed, commit_output, _commitment) = commit_bytes(cfg, &data)?;

		// --- 2. Sample evaluation point & compute claim ---
		let eval_point = pcs.sample_evaluation_point(&mut rng);
		let eval_claim = pcs.calculate_evaluation_claim(&packed.packed_values, &eval_point)?;

		// --- 3. Prove (full control) ---
		let proof = pcs.prove::<B128>(
			&packed.packed_values,
			&packed.packed_mle,
			&ctx,
			&commit_output,
			&eval_point,
		)?;

		// --- 4. Verify ---
		pcs.verify(&proof, &ctx)?;

		// Sanity: proof carries same claim we computed locally
		assert_eq!(proof.evaluation_claim, eval_claim);

		Ok(())
	}

	#[test]
	fn end_to_end_inclusion_proofs() -> Result<(), FriBiniusError> {
		use binius_verifier::config::B128;
		use rand::seq::SliceRandom;

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

		// sample a few random indices
		let mut indices: Vec<usize> = (0..codeword_len).collect();
		indices.shuffle(&mut rng);
		let indices = &indices[..usize::min(16, codeword_len)];

		for &idx in indices {
			let value = commit_output.codeword[idx];

			// create Merkle inclusion proof
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;

			// verify it
			pcs.verify_inclusion_proof(&mut transcript, &[value], idx, &ctx, &commitment)?;
		}

		Ok(())
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

		// "Block producer" side: compute commitments for each blob
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

		// "Light client" side:
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

		// --- 1) Honest proof should verify ---
		{
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;
			pcs.verify_inclusion_proof(&mut transcript, &[honest_value], idx, &ctx, &commitment)?;
		}

		// --- 2) Corrupted value should fail ---
		{
			let mut transcript = pcs.inclusion_proof::<B128>(&commit_output.committed, idx)?;
			let mut bad_value = honest_value;
			// change the original value
			bad_value += B128::from(1u128);

			let res =
				pcs.verify_inclusion_proof(&mut transcript, &[bad_value], idx, &ctx, &commitment);

			assert!(res.is_err(), "verification should fail for corrupted value");
		}

		// --- 3) Corrupted commitment should fail ---
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
}
