#[cfg(test)]
mod e2e_tests {
	use crate::e2e_helpers::*;
	use crate::{FriBiniusError, FriParamsConfig};
	use rand::{SeedableRng, rngs::StdRng};

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
}
