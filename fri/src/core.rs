use crate::config::FriParamsConfig;
use crate::error::FriBiniusError;
use crate::transcript::{Challenger, VerifierTr};

use binius_field::{ExtensionField, Field, PackedExtension, PackedField};
use binius_math::{
	BinarySubspace, FieldBuffer, ReedSolomonCode,
	inner_product::inner_product,
	multilinear::eq::eq_ind_partial_eval,
	ntt::{
		NeighborsLastMultiThread,
		domain_context::{self, GenericPreExpanded},
	},
};
use binius_prover::{
	fri::CommitOutput,
	hash::parallel_compression::ParallelCompressionAdaptor,
	merkle_tree::{MerkleTreeProver, prover::BinaryMerkleTreeProver},
	pcs::OneBitPCSProver,
};
use binius_transcript::ProverTranscript;
use binius_verifier::{
	config::{B1, B128},
	fri::FRIParams,
	hash::{StdCompression, StdDigest},
	merkle_tree::MerkleTreeScheme,
	pcs::verify as fri_verify,
};

#[cfg(test)]
use rand::{CryptoRng, RngCore};
#[cfg(test)]
use binius_field::Random;

// Concrete merkle prover type we’ll use everywhere.
pub type DefaultMerkleProver =
	BinaryMerkleTreeProver<B128, StdDigest, ParallelCompressionAdaptor<StdCompression>>;

/// The committed Merkle-tree data type for a given scalar field.
pub type MerkleCommitted<S> = <BinaryMerkleTreeProver<
	S,
	StdDigest,
	ParallelCompressionAdaptor<StdCompression>,
> as MerkleTreeProver<S>>::Committed;

/// Our PCS commit output type specialization.
pub type FriCommitOutput<P> = CommitOutput<P, Vec<u8>, MerkleCommitted<<P as PackedField>::Scalar>>;

/// Commitment object that we can serialize.
#[derive(Clone, Debug)]
pub struct FriCommitment {
	pub digest: [u8; 32],
}

/// Evaluation proof object that we can propagate.
#[derive(Clone, Debug)]
pub struct FriProof {
	pub commitment: FriCommitment,
	pub evaluation_point: Vec<B128>,
	pub evaluation_claim: B128,
	pub transcript_bytes: Vec<u8>,
}

/// Context holding FRI parameters + NTT domain.
pub struct FriContext {
	pub fri_params: FRIParams<B128>,
	pub ntt: NeighborsLastMultiThread<GenericPreExpanded<B128>>,
}

pub struct FriBiniusPCS {
	cfg: FriParamsConfig,
	merkle_prover: DefaultMerkleProver,
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

	pub fn initialize_fri_context<P>(
		&self,
		packed_buffer: &FieldBuffer<P>,
	) -> Result<FriContext, FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		let committed_rs_code =
			ReedSolomonCode::<B128>::new(packed_buffer.log_len(), self.cfg.log_inv_rate)
				.map_err(|e| FriBiniusError::ReedSolomonInit(e.to_string()))?;

		let fri_log_batch_size = 0;

		let fri_arities = if P::LOG_WIDTH == 2 {
			vec![2, 2]
		} else {
			vec![2; packed_buffer.log_len() / 2]
		};

		let fri_params = FRIParams::new(
			committed_rs_code.clone(),
			fri_log_batch_size,
			fri_arities,
			self.cfg.num_test_queries,
		)
		.map_err(|e| FriBiniusError::FriParamsInit(e.to_string()))?;

		let subspace = BinarySubspace::with_dim(fri_params.rs_code().log_len())
			.map_err(|e| FriBiniusError::DomainInit(e.to_string()))?;

		let domain_context = domain_context::GenericPreExpanded::generate_from_subspace(&subspace);
		let ntt = NeighborsLastMultiThread::new(domain_context, self.cfg.log_num_shares);

		Ok(FriContext { fri_params, ntt })
	}

    #[cfg(test)]
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
		// convert large-field MLE -> small-field MLE over B1
		let small_mle = large_field_mle_to_small_field::<B1, B128>(values);
		let lifted = lift_small_to_large_field::<B1, B128>(&small_mle);

		let eq_vals = eq_ind_partial_eval(evaluation_point).as_ref().to_vec();

		Ok(inner_product::<B128>(lifted, eq_vals))
	}

	pub fn commit<P>(
		&self,
		packed_mle: &FieldBuffer<P>,
		ctx: &FriContext,
	) -> Result<FriCommitOutput<P>, FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		let pcs = OneBitPCSProver::new(&ctx.ntt, &self.merkle_prover, &ctx.fri_params);

		let commit_output = pcs
			.commit(packed_mle.clone())
			.map_err(|e| FriBiniusError::Commitment(e.to_string()))?;

		Ok(CommitOutput {
			codeword: commit_output.codeword,
			commitment: commit_output.commitment.to_vec(),
			committed: commit_output.committed,
		})
	}

	/// Generate a FRI evaluation proof.
	pub fn prove<P>(
		&self,
		values: &[B128],
		packed_mle: &FieldBuffer<P>,
		ctx: &FriContext,
		commit_output: &FriCommitOutput<P>,
		evaluation_point: &[B128],
	) -> Result<FriProof, FriBiniusError>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		// 1) Compute evaluation claim from scalar values
		let evaluation_claim = self.calculate_evaluation_claim(values, evaluation_point)?;

		// 2) Set up PCS prover and transcript
		let pcs = OneBitPCSProver::new(&ctx.ntt, &self.merkle_prover, &ctx.fri_params);
		let mut prover_transcript = ProverTranscript::new(Challenger::default());

		// First write commitment bytes into transcript
		prover_transcript
			.message()
			.write_bytes(&commit_output.commitment);

		// 3) Run FRI proof generation
		pcs.prove(
			&commit_output.codeword,
			&commit_output.committed,
			packed_mle.clone(),
			evaluation_point.to_vec(),
			&mut prover_transcript,
		)
		.map_err(|e| FriBiniusError::Proof(e.to_string()))?;

		// 4) Turn prover transcript into verifier transcript and serialize it
		let verifier_transcript: VerifierTr = prover_transcript.into_verifier();
		let transcript_bytes = crate::transcript::transcript_to_bytes(&verifier_transcript);

		// 5) Extract commitment digest as [u8; 32]
		let digest: [u8; 32] = commit_output
			.commitment
			.as_slice()
			.try_into()
			.expect("commitment is 32 bytes by construction");

		Ok(FriProof {
			commitment: FriCommitment { digest },
			evaluation_point: evaluation_point.to_vec(),
			evaluation_claim,
			transcript_bytes,
		})
	}

	/// Verify a proof produced by `prove`.
	pub fn verify(&self, proof: &FriProof, ctx: &FriContext) -> Result<(), FriBiniusError> {
		// Reconstruct transcript from bytes
		let mut transcript =
			crate::transcript::transcript_from_bytes(proof.transcript_bytes.clone());

		let retrieved_commitment = transcript
			.message()
			.read()
			.map_err(|e| FriBiniusError::Transcript(e.to_string()))?;

		let merkle_scheme = self.merkle_prover.scheme().clone();

		// Call the Binius FRI verification routine
		fri_verify(
			&mut transcript,
			proof.evaluation_claim,
			&proof.evaluation_point,
			retrieved_commitment,
			&ctx.fri_params,
			&merkle_scheme,
		)
		.map_err(|e| FriBiniusError::Verification(e.to_string()))
	}

	/// Inclusion proof: Merkle opening for a particular codeword index.
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

	/// Verify inclusion proof for a given leaf.
	pub fn verify_inclusion_proof(
		&self,
		verifier_transcript: &mut VerifierTr,
		data: &[B128],
		index: usize,
		ctx: &FriContext,
		commitment: &FriCommitment,
	) -> Result<(), FriBiniusError> {
		let tree_depth = ctx.fri_params.rs_code().log_len();

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

// Helper conversions at bottom
fn lift_small_to_large_field<F, FE>(small_field_elms: &[F]) -> Vec<FE>
where
	F: Field,
	FE: Field + ExtensionField<F>,
{
	small_field_elms.iter().map(|&elm| FE::from(elm)).collect()
}

fn large_field_mle_to_small_field<F, FE>(large_field_mle: &[FE]) -> Vec<F>
where
	F: Field,
	FE: Field + ExtensionField<F>,
{
	large_field_mle
		.iter()
		.flat_map(|elm| ExtensionField::<F>::iter_bases(elm))
		.collect()
}
