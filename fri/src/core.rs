use crate::error::FriBiniusError;
use crate::transcript::{transcript_from_bytes, Challenger, VerifierTr};

use binius_field::{PackedExtension, PackedField};
#[cfg(feature = "std")]
use binius_iop::fri::{vcs_optimal_layers_depths_iter, ConstantArityStrategy};
use binius_math::{
	inner_product::inner_product,
	multilinear::eq::eq_ind_partial_eval,
	ntt::{
		domain_context::{self, GenericPreExpanded},
		NeighborsLastMultiThread,
	},
};
#[cfg(feature = "std")]
use binius_math::{BinarySubspace, FieldBuffer};
#[cfg(feature = "std")]
use binius_prover::fri::FRIQueryProver;
use binius_prover::{
	fri::CommitOutput,
	hash::parallel_compression::ParallelCompressionAdaptor,
	merkle_tree::{prover::BinaryMerkleTreeProver, MerkleTreeProver},
};
#[cfg(feature = "std")]
use binius_spartan_prover::pcs::PCSProver;
#[cfg(feature = "std")]
use binius_spartan_verifier::pcs::verify as spartan_verify;
use binius_transcript::ProverTranscript;
#[cfg(feature = "std")]
use binius_verifier::merkle_tree::BinaryMerkleTreeScheme;
use binius_verifier::{
	config::B1,
	fri::FRIParams,
	hash::{StdCompression, StdDigest},
	merkle_tree::MerkleTreeScheme,
};
#[cfg(feature = "std")]
use itertools::izip;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// TODO: re-export some of the common types to be used by downstream
pub use avail_core::{FriParamsConfig, FriParamsVersion};
pub use binius_verifier::config::B128;

#[cfg(any(test, feature = "bench"))]
use binius_field::Random;
#[cfg(any(test, feature = "bench"))]
use rand::{CryptoRng, RngCore};

// Concrete merkle prover type we’ll use everywhere.
pub type DefaultMerkleProver =
	BinaryMerkleTreeProver<B128, StdDigest, ParallelCompressionAdaptor<StdCompression>>;

/// The committed Merkle-tree data type for a given scalar field.
pub type MerkleCommitted<S> = <BinaryMerkleTreeProver<
	S,
	StdDigest,
	ParallelCompressionAdaptor<StdCompression>,
> as MerkleTreeProver<S>>::Committed;

pub type FriCommitOutput<P> =
	CommitOutput<P, digest::Output<StdDigest>, MerkleCommitted<<P as PackedField>::Scalar>>;

#[cfg(feature = "std")]
pub type FriQueryProver<'a, P> = FRIQueryProver<
	'a,
	B128,
	P,
	DefaultMerkleProver,
	BinaryMerkleTreeScheme<B128, StdDigest, StdCompression>,
>;

#[derive(Clone, Debug)]
pub struct FriCommitment {
	pub digest: [u8; 32],
	pub depth: usize,
}

/// Evaluation proof
#[derive(Clone, Debug)]
pub struct FriProof {
	pub transcript_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SamplingProof {
	/// Index of the codeword
	pub index: u32,
	/// Canonical B128 value, LE-encoded (16 bytes)
	pub cell: Vec<u8>,
	/// Serialized inclusion proof transcript
	pub proof: Vec<u8>,
}

impl SamplingProof {
	pub fn new(index: u32, cell: Vec<u8>, proof: Vec<u8>) -> Self {
		Self { index, cell, proof }
	}

	pub fn verify_b128(
		&self,
		pcs: &FriBiniusPCS,
		ctx: &FriContext,
		commitment: &FriCommitment,
	) -> Result<(), FriBiniusError> {
		if self.cell.is_empty() || !self.cell.len().is_multiple_of(16) {
			return Err(FriBiniusError::InvalidInput(
				"SamplingProof.cell must be a non-empty multiple of 16 bytes".into(),
			));
		}

		let values = self
			.cell
			.chunks_exact(16)
			.map(|chunk| {
				let mut arr = [0u8; 16];
				arr.copy_from_slice(chunk);
				B128::from(u128::from_le_bytes(arr))
			})
			.collect::<Vec<_>>();
		let mut transcript = transcript_from_bytes(self.proof.clone());

		pcs.verify_inclusion_proof(
			&mut transcript,
			&values,
			self.index as usize,
			ctx,
			commitment,
		)
	}
}
/// Context holding FRI parameters + NTT domain.
pub struct FriContext {
	pub fri_params: FRIParams<B128>,
	pub ntt: NeighborsLastMultiThread<GenericPreExpanded<B128>>,
}

pub struct FriBiniusPCS {
	pub(crate) cfg: FriParamsConfig,
	pub(crate) merkle_prover: DefaultMerkleProver,
}

impl FriBiniusPCS {
	pub fn new(cfg: FriParamsConfig) -> Self {
		Self {
			merkle_prover: DefaultMerkleProver::new(ParallelCompressionAdaptor::new(
				StdCompression::default(),
			)),
			cfg,
		}
	}

	#[cfg(feature = "std")]
	pub fn initialize_fri_context<P>(
		&self,
		mle_log_len: usize,
	) -> Result<FriContext, FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		let code_log_len = mle_log_len + self.cfg.log_inv_rate;
		let subspace = BinarySubspace::with_dim(code_log_len);

		let domain_context = domain_context::GenericPreExpanded::generate_from_subspace(&subspace);
		let ntt = NeighborsLastMultiThread::new(domain_context, self.cfg.log_num_shares);

		let fri_params = FRIParams::with_strategy(
			&ntt,
			self.merkle_prover.scheme(),
			mle_log_len,
			None,
			self.cfg.log_inv_rate,
			self.cfg.num_test_queries,
			&ConstantArityStrategy::new(2),
		)
		.map_err(|e| FriBiniusError::FriParamsInit(e.to_string()))?;

		Ok(FriContext { fri_params, ntt })
	}

	#[cfg(any(test, feature = "bench"))]
	pub fn sample_evaluation_point<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<B128> {
		let mut point = Vec::with_capacity(self.cfg.n_vars);
		for _ in 0..self.cfg.n_vars {
			point.push(B128::random(&mut *rng));
		}
		point
	}

	pub fn calculate_evaluation_claim(
		&self,
		values: &[B128],
		evaluation_point: &[B128],
	) -> Result<B128, FriBiniusError> {
		if !values.len().is_power_of_two() {
			return Err(FriBiniusError::InvalidInput(
				"values length must be a power of two".into(),
			));
		}

		let required_n_vars = values.len().ilog2() as usize;
		if evaluation_point.len() < required_n_vars {
			return Err(FriBiniusError::InvalidEvaluationPoint(
				required_n_vars,
				evaluation_point.len(),
			));
		}

		let eval_slice = &evaluation_point[..required_n_vars];
		let evaluation_claim = inner_product::<B128>(
			values.to_vec(),
			eq_ind_partial_eval(eval_slice)
				.as_ref()
				.iter()
				.copied()
				.collect::<Vec<_>>(),
		);
		Ok(evaluation_claim)
	}

	#[cfg(feature = "std")]
	pub fn commit<P>(
		&self,
		packed_mle: &FieldBuffer<P>,
		ctx: &FriContext,
	) -> Result<FriCommitOutput<P>, FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		let pcs = PCSProver::new(&ctx.ntt, &self.merkle_prover, &ctx.fri_params);
		pcs.commit(packed_mle.to_ref())
			.map_err(|e| FriBiniusError::Commitment(e.to_string()))
	}

	#[cfg(feature = "std")]
	pub fn prove_with_openings<'a, P>(
		&'a self,
		packed_mle: FieldBuffer<P>,
		ctx: &'a FriContext,
		commit_output: &'a FriCommitOutput<P>,
		evaluation_point: &[B128],
	) -> Result<(FieldBuffer<B128>, FriQueryProver<'a, P>, FriProof), FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		let n_packed_vars = ctx.fri_params.rs_code().log_dim() + ctx.fri_params.log_batch_size();
		if evaluation_point.len() < n_packed_vars {
			return Err(FriBiniusError::InvalidEvaluationPoint(
				n_packed_vars,
				evaluation_point.len(),
			));
		}
		let eval_point = &evaluation_point[..n_packed_vars];

		let eval_point_eq = eq_ind_partial_eval::<P>(eval_point);
		let evaluation_claim =
			binius_math::inner_product::inner_product_buffers(&packed_mle, &eval_point_eq);

		let pcs = PCSProver::new(&ctx.ntt, &self.merkle_prover, &ctx.fri_params);
		let mut prover_transcript = ProverTranscript::new(Challenger::default());
		prover_transcript.message().write(&commit_output.commitment);

		let (terminate_codeword, query_prover) = pcs
			.prove_with_openings(
				commit_output.codeword.clone(),
				&commit_output.committed,
				packed_mle,
				eval_point,
				evaluation_claim,
				&mut prover_transcript,
			)
			.map_err(|e| FriBiniusError::Proof(e.to_string()))?;

		let proof = FriProof {
			transcript_bytes: prover_transcript.finalize(),
		};

		Ok((terminate_codeword, query_prover, proof))
	}

	#[cfg(feature = "std")]
	pub fn prove<P>(
		&self,
		packed_mle: FieldBuffer<P>,
		ctx: &FriContext,
		commit_output: &FriCommitOutput<P>,
		evaluation_point: &[B128],
	) -> Result<FriProof, FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		let (_, _, proof) =
			self.prove_with_openings(packed_mle, ctx, commit_output, evaluation_point)?;
		Ok(proof)
	}

	#[cfg(feature = "std")]
	pub fn verify(
		&self,
		proof: &FriProof,
		evaluation_claim: B128,
		evaluation_point: &[B128],
		ctx: &FriContext,
	) -> Result<(), FriBiniusError> {
		let mut transcript = transcript_from_bytes(proof.transcript_bytes.clone());
		let retrieved_commitment = transcript
			.message()
			.read()
			.map_err(|e| FriBiniusError::Transcript(e.to_string()))?;

		let n_packed_vars = ctx.fri_params.rs_code().log_dim() + ctx.fri_params.log_batch_size();
		if evaluation_point.len() < n_packed_vars {
			return Err(FriBiniusError::InvalidEvaluationPoint(
				n_packed_vars,
				evaluation_point.len(),
			));
		}
		let eval_point = &evaluation_point[..n_packed_vars];

		let merkle_scheme = self.merkle_prover.scheme().clone();
		spartan_verify(
			&mut transcript,
			evaluation_claim,
			eval_point,
			retrieved_commitment,
			&ctx.fri_params,
			&merkle_scheme,
		)
		.map_err(|e| FriBiniusError::Verification(e.to_string()))?;

		Ok(())
	}

	#[cfg(feature = "std")]
	pub fn verify_with_extra_query(
		&self,
		proof: &FriProof,
		evaluation_claim: B128,
		evaluation_point: &[B128],
		ctx: &FriContext,
		extra_index: usize,
		terminate_codeword: &[B128],
		layers: &[Vec<digest::Output<StdDigest>>],
		extra_transcript: &mut VerifierTr,
	) -> Result<(), FriBiniusError> {
		let mut transcript = transcript_from_bytes(proof.transcript_bytes.clone());
		let retrieved_commitment = transcript
			.message()
			.read()
			.map_err(|e| FriBiniusError::Transcript(e.to_string()))?;

		let n_packed_vars = ctx.fri_params.rs_code().log_dim() + ctx.fri_params.log_batch_size();
		if evaluation_point.len() < n_packed_vars {
			return Err(FriBiniusError::InvalidEvaluationPoint(
				n_packed_vars,
				evaluation_point.len(),
			));
		}
		let eval_point = &evaluation_point[..n_packed_vars];

		let merkle_scheme = self.merkle_prover.scheme().clone();
		let verifier_with_arena = spartan_verify(
			&mut transcript,
			evaluation_claim,
			eval_point,
			retrieved_commitment,
			&ctx.fri_params,
			&merkle_scheme,
		)
		.map_err(|e| FriBiniusError::Verification(e.to_string()))?;

		let verifier = verifier_with_arena.verifier();

		for (commitment, layer_depth, layer) in izip!(
			std::iter::once(verifier.codeword_commitment).chain(verifier.round_commitments),
			vcs_optimal_layers_depths_iter(verifier.params, verifier.vcs),
			layers
		) {
			verifier
				.vcs
				.verify_layer(commitment, layer_depth, layer)
				.map_err(|e| FriBiniusError::Verification(e.to_string()))?;
		}

		let mut advice = extra_transcript.decommitment();
		verifier
			.verify_query(
				extra_index,
				&ctx.ntt,
				terminate_codeword,
				layers,
				&mut advice,
			)
			.map_err(|e| FriBiniusError::Verification(e.to_string()))?;

		Ok(())
	}

	pub fn inclusion_proof<P>(
		&self,
		committed: &MerkleCommitted<P::Scalar>,
		index: usize,
	) -> Result<VerifierTr, FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		let mut proof_writer = ProverTranscript::new(Challenger::default());
		self.merkle_prover
			.prove_opening(committed, 0, index, &mut proof_writer.message())
			.map_err(|e| FriBiniusError::Merkle(e.to_string()))?;

		Ok(proof_writer.into_verifier())
	}

	#[cfg(feature = "std")]
	pub fn open<'a, P>(
		&self,
		index: usize,
		query_prover: &FriQueryProver<'a, P>,
	) -> Result<VerifierTr, FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		let mut proof_transcript = ProverTranscript::new(Challenger::default());
		let mut advice = proof_transcript.decommitment();

		query_prover
			.prove_query(index, &mut advice)
			.map_err(|e| FriBiniusError::Proof(e.to_string()))?;

		Ok(proof_transcript.into_verifier())
	}

	pub fn verify_inclusion_proof(
		&self,
		verifier_transcript: &mut VerifierTr,
		data: &[B128],
		index: usize,
		_ctx: &FriContext,
		commitment: &FriCommitment,
	) -> Result<(), FriBiniusError> {
		let tree_depth = commitment.depth;

		self.merkle_prover
			.scheme()
			.verify_opening(
				index,
				data,
				0,
				tree_depth,
				&[commitment.digest.into()],
				&mut verifier_transcript.message(),
			)
			.map_err(|e| FriBiniusError::Merkle(e.to_string()))
	}
}
