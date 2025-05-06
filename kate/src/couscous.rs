#![deny(clippy::arithmetic_side_effects)]

use core::convert::TryInto;
use poly_multiproof::{
	ark_serialize::CanonicalDeserialize,
	m1_blst::{self, G1, G2},
};
use sp_std::vec::Vec;

// Loads the pre-generated trusted g1 & g2 from the file
fn load_trusted_g1_g2() -> (Vec<G1>, Vec<G2>) {
	// for degree = 1024
	let contents = include_str!("g1_g2_1024.txt");
	let mut lines = contents.lines();
	let g1_len: usize = lines.next().unwrap().parse().unwrap();
	let g2_len: usize = lines.next().unwrap().parse().unwrap();

	let g1_bytes: Vec<[u8; 48]> = lines
		.by_ref()
		.take(g1_len)
		.map(|line| hex::decode(line).unwrap().try_into().unwrap())
		.collect();

	let g2_bytes: Vec<[u8; 96]> = lines
		.take(g2_len)
		.map(|line| hex::decode(line).unwrap().try_into().unwrap())
		.collect();

	let g1: Vec<G1> = g1_bytes
		.iter()
		.map(|bytes| G1::deserialize_compressed(&bytes[..]).unwrap())
		.collect();

	let g2: Vec<G2> = g2_bytes
		.iter()
		.map(|bytes| G2::deserialize_compressed(&bytes[..]).unwrap())
		.collect();

	(g1, g2)
}

///  Construct public parameters from pre-generated points for degree upto 1024
pub fn multiproof_params() -> m1_blst::M1NoPrecomp {
	let (g1, g2) = load_trusted_g1_g2();
	m1_blst::M1NoPrecomp::new_from_powers(g1, g2)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;
	use pmp::{
		ark_poly::{
			univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
			GeneralEvaluationDomain,
		},
		traits::KZGProof,
	};
	use poly_multiproof::{m1_blst::Fr, traits::Committer};
	use rand::thread_rng;

	#[test]
	fn test_testnet_params() {
		let pmp = multiproof_params();

		let points = DensePolynomial::<Fr>::rand(1023, &mut thread_rng()).coeffs;
		let pmp_ev = GeneralEvaluationDomain::<Fr>::new(1024).unwrap();
		let pmp_poly = pmp_ev.ifft(&points);
		let pmp_domain_pts = pmp_ev.elements().collect::<Vec<_>>();

		let pmp_commit = pmp.commit(&pmp_poly).unwrap();

		let proof = pmp
			.open(
				pmp.compute_witness_polynomial(pmp_poly, pmp_domain_pts[1])
					.unwrap(),
			)
			.unwrap();

		let verify1 = pmp
			.verify(&pmp_commit, pmp_domain_pts[1], points[1], &proof)
			.unwrap();

		assert!(verify1);
	}
}

// vim: set noet nowrap
