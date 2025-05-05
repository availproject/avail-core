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
	pub type ArkScalar = poly_multiproof::m1_blst::Fr;
	pub type ArkEvaluationDomain = poly_multiproof::ark_poly::GeneralEvaluationDomain<ArkScalar>;
}
