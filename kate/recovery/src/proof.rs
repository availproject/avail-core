use core::convert::TryInto;
use thiserror_no_std::Error;

use crate::commons::ArkScalar;
use avail_core::constants::kate::COMMITMENT_SIZE;
use poly_multiproof::{
	ark_bls12_381::{Bls12_381, Fr},
	ark_poly::{EvaluationDomain as ArkEvaluationDomain, GeneralEvaluationDomain},
	merlin::Transcript,
	method1::{M1NoPrecomp, Proof as ArkProof},
	msm::blst::BlstMSMEngine,
	traits::{AsBytes, KZGProof, PolyMultiProofNoPrecomp},
};
use sp_std::vec::Vec;
type ArkCommitment = poly_multiproof::Commitment<Bls12_381>;
use crate::{
	data::{GCellBlock, SingleCell},
	matrix::Dimensions,
};

#[derive(Error, Debug)]
pub enum Error {
	#[error("Proof, data or commitment is not valid")]
	InvalidData,
	#[error("Evaluation domain is not valid for given dimensions")]
	InvalidDomain,
	#[error("Public parameters degree is to small for given dimensions")]
	InvalidDegree,
	#[error("Position isn't in domain")]
	InvalidPositionInDomain,
	#[error("Failed to generate domain points")]
	FailedToGenerateDomainPoints,
	#[error("Failed to convert evals to ArkScalar")]
	FailedToConvertEvalsToArkScalar,
	#[error("Failed to parse proof")]
	FailedToParseProof,
	#[error("Failed to extract Commitments")]
	FailedToExtractCommitments,
	#[error("Failed to verify proof")]
	FailedToVerifyProof,
}

/// Verifies proof for a given cell using arkworks primitives.
pub fn verify_v2(
	public_parameters: &M1NoPrecomp<Bls12_381, BlstMSMEngine>,
	dimensions: Dimensions,
	commitment: &[u8; COMMITMENT_SIZE],
	cell: &SingleCell,
) -> Result<bool, Error> {
	// Deserialize commitment
	let commitment = ArkCommitment::from_bytes(commitment).map_err(|_| Error::InvalidData)?;

	// Deserialize evaluation (cell value)
	let value = ArkScalar::from_bytes(&cell.data()).map_err(|_| Error::InvalidData)?;

	// Get the domain point from the cell position
	let domain_point = GeneralEvaluationDomain::<Fr>::new(dimensions.width())
		.ok_or(Error::InvalidDomain)?
		.element(cell.position.col.into());

	// Deserialize proof
	let proof = ArkProof::from_bytes(&cell.proof()).map_err(|_| Error::InvalidData)?;

	// Verify the proof
	KZGProof::verify::<BlstMSMEngine>(public_parameters, &commitment, domain_point, value, &proof)
		.map_err(|_| Error::InvalidData)
}

/// Generates domain points for a given size using arkworks primitives.
pub fn domain_points(n: usize) -> Result<Vec<ArkScalar>, Error> {
	let domain = GeneralEvaluationDomain::<ArkScalar>::new(n).ok_or(Error::InvalidDomain)?;
	Ok(domain.elements().collect())
}

#[allow(clippy::type_complexity)]
/// Verifies a multi-proof for multiple cells with single proof using arkworks primitives.
pub async fn verify_multi_proof(
	pmp: &M1NoPrecomp<Bls12_381, BlstMSMEngine>,
	proof: &[((Vec<[u8; 32]>, [u8; 48]), GCellBlock)],
	commitments: &[u8],
	cols: usize, // Number of columns in the original grid
) -> Result<bool, Error> {
	let points = domain_points(cols)?;
	for ((eval, proof), cellblock) in proof.iter() {
		let evals_flat = eval
			.iter()
			.map(ArkScalar::from_bytes)
			.collect::<Result<Vec<_>, _>>()
			.map_err(|_| Error::FailedToConvertEvalsToArkScalar)?;
		let evals_grid = evals_flat
			.chunks_exact((cellblock.end_x - cellblock.start_x) as usize)
			.collect::<Vec<_>>();

		let proofs = ArkProof::from_bytes(proof).map_err(|_| Error::FailedToParseProof)?;

		let commits = commitments
			.chunks_exact(48)
			.skip(cellblock.start_y as usize)
			.take((cellblock.end_y - cellblock.start_y) as usize)
			.map(|c| ArkCommitment::from_bytes(c.try_into().unwrap()))
			.collect::<Result<Vec<_>, _>>()
			.map_err(|_| Error::FailedToExtractCommitments)?;

		let verified = PolyMultiProofNoPrecomp::verify(
			pmp,
			&mut Transcript::new(b"avail-mp"),
			&commits[..],
			&points[(cellblock.start_x as usize)..(cellblock.end_x as usize)],
			&evals_grid,
			&proofs,
		)
		.map_err(|_| Error::FailedToVerifyProof)?;
		if !verified {
			return Ok(false);
		}
	}

	Ok(true)
}
