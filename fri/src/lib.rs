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
	DefaultMerkleProver, FriBiniusPCS, FriCommitOutput, FriCommitment, FriContext, FriParamsConfig,
	FriParamsVersion, FriProof, SamplingProof, B128,
};
pub use crate::encoding::{BytesEncoder, PackedMLE};
pub use crate::error::FriBiniusError;

#[cfg(test)]
mod tests;
#[cfg(feature = "testing")]
pub use sampling::reconstruct_codeword_naive;
pub use transcript::{transcript_from_bytes, transcript_to_bytes, VerifierTr};

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

		// Generate proof
		let proof =
			pcs.prove::<B128>(packed.packed_mle.clone(), &ctx, &commit_output, &eval_point)?;

		// Verify
		pcs.verify(&proof, eval_claim, &eval_point, &ctx)
	}
}
