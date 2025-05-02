use thiserror_no_std::Error;

#[cfg(feature = "std")]
use avail_core::constants::kate::COMMITMENT_SIZE;
#[cfg(feature = "std")]
use dusk_bytes::Serializable;
#[cfg(feature = "std")]
use dusk_plonk::{
	bls12_381::G1Affine,
	commitment_scheme::kzg10::{commitment::Commitment, proof::Proof, PublicParameters},
	fft::EvaluationDomain,
	prelude::BlsScalar,
};
#[cfg(feature = "std")]
use poly_multiproof::{
	ark_bls12_381::{Bls12_381, Fr},
	ark_poly::{EvaluationDomain as ArkEvaluationDomain, GeneralEvaluationDomain},
	method1::{M1NoPrecomp, Proof as ArkProof},
	msm::blst::BlstMSMEngine,
	traits::{AsBytes, KZGProof},
};

#[cfg(feature = "std")]
type ArkScalar = poly_multiproof::ark_bls12_381::Fr;
#[cfg(feature = "std")]
type ArkCommitment = poly_multiproof::Commitment<Bls12_381>;

#[cfg(feature = "std")]
use crate::data::SingleCell;
#[cfg(feature = "std")]
use crate::matrix::Dimensions;

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

#[cfg(feature = "std")]
impl From<dusk_bytes::Error> for Error {
	fn from(_: dusk_bytes::Error) -> Self {
		Error::InvalidData
	}
}

/// Verifies proof for given cell
///
/// # Deprecated
/// This function is deprecated. Use [`verify_v2`] instead, which uses arkworks primitives.
#[deprecated(
	note = "This function is deprecated. Use `verify_v2` instead, which uses arkworks primitives."
)]
#[cfg(feature = "std")]
pub fn verify(
	public_parameters: &PublicParameters,
	dimensions: Dimensions,
	commitment: &[u8; COMMITMENT_SIZE],
	cell: &SingleCell,
) -> Result<bool, Error> {
	let commitment_to_witness = G1Affine::from_bytes(&cell.proof()).map(Commitment::from)?;

	let evaluated_point = BlsScalar::from_bytes(&cell.data())?;

	let commitment_to_polynomial = G1Affine::from_bytes(commitment).map(Commitment::from)?;

	let proof = Proof {
		commitment_to_witness,
		evaluated_point,
		commitment_to_polynomial,
	};

	let cols: usize = dimensions.width();
	let point = EvaluationDomain::new(cols)
		.map_err(|_| Error::InvalidDomain)?
		.elements()
		.nth(cell.position.col.into())
		.ok_or(Error::InvalidPositionInDomain)?;

	Ok(public_parameters.opening_key().check(point, proof))
}

/// Verifies proof for a given cell using arkworks primitives.
#[cfg(feature = "std")]
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
		.verify::<BlstMSMEngine>(&commitment, domain_point, value, &proof)
		.map_err(|_| Error::InvalidData)
}
