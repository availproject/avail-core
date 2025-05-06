use thiserror_no_std::Error;

#[cfg(feature = "std")]
use crate::{data::Cell, matrix::Dimensions};
#[cfg(feature = "std")]
use avail_core::constants::kate::COMMITMENT_SIZE;

#[cfg(feature = "std")]
use poly_multiproof::traits::AsBytes;
#[cfg(feature = "std")]
use poly_multiproof::{
	ark_poly::{EvaluationDomain as ArkEvaluationDomain, GeneralEvaluationDomain},
	m1_blst::{Bls12_381, Fr, M1NoPrecomp, Proof as ArkProof},
	traits::KZGProof,
};

#[cfg(feature = "std")]
use crate::commons::ArkScalar;
#[cfg(feature = "std")]
type ArkCommitment = poly_multiproof::Commitment<Bls12_381>;

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
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Verifies proof for a given cell using arkworks primitives.
#[cfg(feature = "std")]
pub fn verify_v2(
	public_parameters: &M1NoPrecomp,
	dimensions: Dimensions,
	commitment: &[u8; COMMITMENT_SIZE],
	cell: &Cell,
) -> Result<bool, Error> {
	// Deserialize commitment
	let commitment = ArkCommitment::from_bytes(commitment).map_err(|_| Error::InvalidData)?;

	// Deserialize evaluation (cell value)
	let value = ArkScalar::from_bytes(&cell.data()).map_err(|_| Error::InvalidData)?;

	// Get the domain point fromthe cell position
	let domain_point = GeneralEvaluationDomain::<Fr>::new(dimensions.width())
		.ok_or(Error::InvalidDomain)?
		.elements()
		.nth(cell.position.col.into())
		.ok_or(Error::InvalidPositionInDomain)?;

	// Deserialize proof
	let proof = ArkProof::from_bytes(&cell.proof()).map_err(|_| Error::InvalidData)?;

	// Verify the proof
	public_parameters
		.verify(&commitment, domain_point, value, &proof)
		.map_err(|_| Error::InvalidData)
}
