pub mod core;
pub mod encoding;
pub mod error;
#[cfg(feature = "testing")]
pub mod sampling;
pub mod transcript;

#[cfg(test)]
mod tests;

pub use avail_core::FriParamsConfig;
pub use core::{FriBiniusPCS, FriCommitment, FriContext, FriProof};
pub use encoding::{BytesEncoder, PackedMLE};
pub use error::FriBiniusError;
#[cfg(feature = "testing")]
pub use sampling::reconstruct_codeword_naive;
pub use transcript::{transcript_from_bytes, transcript_to_bytes, VerifierTr};

#[cfg(test)]
pub mod e2e_helpers {
	use crate::core::FriCommitOutput;

	use super::*;
	use binius_verifier::config::B128;
	use rand::{CryptoRng, RngCore};

	/// Prepare everything from raw bytes up to a commitment:
	/// - bytes -> PackedMLE<B128>
	/// - derive `n_vars` from the data
	/// - build PCS + context
	/// - commit
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

		// fill in n_vars from data (UX: user doesn't have to know it)
		cfg.n_vars = packed.total_n_vars;

		// PCS + FRI context
		let pcs = FriBiniusPCS::new(cfg);
		let ctx = pcs.initialize_fri_context::<B128>(packed.packed_mle.log_len())?;

		// Commit
		let commit_output = pcs.commit::<B128>(&packed.packed_mle, &ctx)?;
		let digest: [u8; 32] = commit_output
			.commitment
			.as_slice()
			.try_into()
			.expect("Binius commitment is 32 bytes");

		let commitment = FriCommitment { digest };

		Ok((pcs, ctx, packed, commit_output, commitment))
	}

	/// Convenience: commit + one evaluation proof + verification.
	pub fn commit_prove_verify_bytes<R: RngCore + CryptoRng>(
		cfg: FriParamsConfig,
		data: &[u8],
		rng: &mut R,
	) -> Result<(), FriBiniusError> {
		let (pcs, ctx, packed, commit_output, _commitment) = commit_bytes(cfg, data)?;

		// Sample evaluation point
		let eval_point = pcs.sample_evaluation_point(rng);

		// Generate proof
		let proof = pcs.prove::<B128>(
			&packed.packed_values,
			&packed.packed_mle,
			&ctx,
			&commit_output,
			&eval_point,
		)?;

		// Verify
		pcs.verify(&proof, &ctx)
	}
}
