use crate::ArkScalar;
use poly_multiproof::ark_bls12_381::Bls12_381;
use poly_multiproof::ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
pub type Commitment = crate::pmp::Commitment<Bls12_381>;
use sp_std::{result::Result, vec::Vec};

pub use poly_multiproof::traits::AsBytes;

pub enum Errors {
	DomainSizeInvalid,
}

pub fn domain_points(n: usize) -> Result<Vec<ArkScalar>, Errors> {
	let domain = GeneralEvaluationDomain::<ArkScalar>::new(n).ok_or(Errors::DomainSizeInvalid)?;
	Ok(domain.elements().collect())
}
