mod core;
mod encoding;
mod error;
#[cfg(feature = "testing")]
mod sampling;
mod transcript;

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
		// 1. bytes -> packed MLE
		let encoder = BytesEncoder::<B128>::new();
		let packed = encoder.bytes_to_packed_mle(data)?;

		// 2. fill in n_vars from data (UX: user doesn't have to know it)
		cfg.n_vars = packed.total_n_vars;

		// 3. PCS + FRI context
		let pcs = FriBiniusPCS::new(cfg);
		let ctx = pcs.initialize_fri_context(&packed.packed_mle)?;

		// 4. Commit
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

		// 1. Sample evaluation point
		let eval_point = pcs.sample_evaluation_point(rng);

		// 2. Generate proof
		let proof = pcs.prove::<B128>(
			&packed.packed_values,
			&packed.packed_mle,
			&ctx,
			&commit_output,
			&eval_point,
		)?;

		// 3. Verify
		pcs.verify(&proof, &ctx)
	}
}
