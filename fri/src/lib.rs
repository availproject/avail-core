pub mod core;
pub mod encoding;
pub mod error;
pub mod eval_utils;
#[cfg(feature = "testing")]
pub mod sampling;
pub mod transcript;

#[cfg(feature = "std")]
pub use crate::core::FriQueryProver;
pub use crate::core::{
	DefaultMerkleProver, FriBiniusPCS, FriCommitOutput, FriCommitment, FriContext,
	FriEvalProofBundle, FriExtraQueryProof, FriParamsConfig, FriParamsVersion, FriProof,
	SamplingProof, B128,
};
pub use crate::encoding::{BytesEncoder, PackedMLE};
pub use crate::error::FriBiniusError;

#[cfg(test)]
mod tests;
#[cfg(feature = "testing")]
pub use sampling::reconstruct_codeword_naive;
pub use transcript::{transcript_from_bytes, transcript_to_bytes, VerifierTr};

#[cfg(feature = "std")]
pub struct BlobCommitment {
	pub commitment: Vec<u8>,
	pub seed: [u8; 32],
	pub claim: [u8; 16],
}

#[cfg(feature = "std")]
impl BlobCommitment {
	pub fn compute(
		randomness: &[u8; 32],
		blob: &[u8],
		blob_hash: &[u8; 32],
	) -> Result<Self, FriBiniusError> {
		compute_blob_commitment(randomness, blob, blob_hash)
	}
}

#[cfg(feature = "std")]
pub fn compute_blob_commitment(
	randomness: &[u8; 32],
	blob: &[u8],
	blob_hash: &[u8; 32],
) -> Result<BlobCommitment, FriBiniusError> {
	let encoder = BytesEncoder::<B128>::new();
	let packed = encoder.bytes_to_packed_mle(blob)?;
	let cfg = FriParamsVersion::V0.to_config(packed.total_n_vars);
	let pcs = FriBiniusPCS::new(cfg);
	let ctx = pcs.initialize_fri_context::<B128>(packed.packed_mle.log_len())?;

	let commit_output = pcs.commit(&packed.packed_mle, &ctx)?;

	let seed = eval_utils::derive_seed_from_inputs(randomness, blob_hash);
	let evaluation_point = eval_utils::derive_evaluation_point(seed, packed.total_n_vars);
	let eval_claim = pcs.calculate_evaluation_claim(&packed.packed_values, &evaluation_point)?;

	let claim: [u8; 16] = eval_utils::eval_claim_to_bytes(eval_claim);
	let commitment = commit_output.commitment.to_vec();

	Ok(BlobCommitment {
		commitment,
		seed,
		claim,
	})
}

#[cfg(any(test, feature = "bench"))]
pub mod e2e_helpers {
	use crate::core::{FriBiniusPCS, FriCommitOutput, FriCommitment, FriContext, B128};
	use crate::encoding::{BytesEncoder, PackedMLE};
	use crate::FriBiniusError;
	use avail_core::FriParamsConfig;
	use rand::{CryptoRng, Rng};

	/// Commit-only helper used in tests/benches.
	pub fn commit_bytes(
		mut cfg: FriParamsConfig,
		data: &[u8],
	) -> Result<
		(
			FriBiniusPCS,
			FriContext,
			PackedMLE<B128>,
			FriCommitOutput<B128>,
			FriCommitment,
		),
		FriBiniusError,
	> {
		// bytes -> packed MLE
		let encoder = BytesEncoder::<B128>::new();
		let packed = encoder.bytes_to_packed_mle(data)?;

		// Fill n_vars from data
		cfg.n_vars = packed.total_n_vars;

		// PCS + FRI context
		let pcs = FriBiniusPCS::new(cfg);
		let ctx = pcs.initialize_fri_context::<B128>(packed.packed_mle.log_len())?;

		// Commit
		let commit_output = pcs.commit::<B128>(&packed.packed_mle, &ctx)?;
		let digest: [u8; 32] = commit_output
			.commitment
			.to_vec()
			.as_slice()
			.try_into()
			.expect("Binius commitment is 32 bytes");

		let commitment = FriCommitment {
			digest,
			depth: commit_output.committed.log_len,
		};

		Ok((pcs, ctx, packed, commit_output, commitment))
	}

	/// Full commit+prove+verify helper.
	pub fn commit_prove_verify_bytes<R: Rng + CryptoRng>(
		cfg: FriParamsConfig,
		data: &[u8],
		rng: &mut R,
	) -> Result<(), FriBiniusError> {
		let (pcs, ctx, packed, commit_output, _commitment) = commit_bytes(cfg, data)?;

		// Sample evaluation point and compute claim
		let eval_point = pcs.sample_evaluation_point(rng);
		let eval_claim = pcs.calculate_evaluation_claim(&packed.packed_values, &eval_point)?;

		// Generate and verify using the extra-query bundle path.
		let (terminate_codeword, query_prover, proof) = pcs.prove_with_openings::<B128>(
			packed.packed_mle.clone(),
			&ctx,
			&commit_output,
			&eval_point,
		)?;
		let extra_index = 0usize;
		let bundle =
			pcs.build_eval_proof_bundle(&proof, &terminate_codeword, &query_prover, extra_index)?;
		pcs.verify_eval_proof_bundle(&bundle, eval_claim, &eval_point, &ctx)
	}
}
