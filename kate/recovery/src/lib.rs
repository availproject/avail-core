#![cfg_attr(not(feature = "std"), no_std)]

pub mod com;
pub mod commitments;
pub mod data;
pub mod matrix;
pub mod proof;
#[cfg(feature = "std")]
pub mod sparse_slice_read;

pub mod testnet;

pub mod commons {
	pub type ArkScalar = poly_multiproof::ark_bls12_381::Fr;
	pub type ArkEvaluationDomain = poly_multiproof::ark_poly::GeneralEvaluationDomain<ArkScalar>;
	pub type ArkPublicParams = poly_multiproof::method1::M1NoPrecomp<
		poly_multiproof::ark_bls12_381::Bls12_381,
		poly_multiproof::msm::blst::BlstMSMEngine,
	>;
}
