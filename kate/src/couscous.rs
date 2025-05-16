#![deny(clippy::arithmetic_side_effects)]

use dusk_plonk::commitment_scheme::kzg10::PublicParameters;

// TODO: load pp for both dusk & arkworks from same file
// To be used for incentivised testnet
use super::*;
use pmp::ark_bls12_381::{G1Projective as G1, G2Projective as G2};
use pmp::ark_serialize::CanonicalDeserialize;
use pmp::method1::M1NoPrecomp;
use pmp::traits::MSMEngine;
use pmp::Pairing;
/// Constructs public parameters from pre-generated points for degree upto 1024
pub fn public_params() -> PublicParameters {
	// We can also use the raw data to make deserilization faster at the cost of size of the data
	let pp_bytes = include_bytes!("pp_1024.data");
	PublicParameters::from_slice(pp_bytes).expect("Deserialization should work")
}

// Loads the pre-generated trusted g1 & g2 from the file
fn load_trusted_g1_g2() -> (Vec<G1>, Vec<G2>) {
	// For degree 1024, we include 513 G2 points.
	// The rationale is that in multiproof constructions, we never need more than half the degree in G2 points.
	// Creating a multiproof grid with width equal to the original data grid doesn't make sense.
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
pub fn multiproof_params<E: Pairing<G1 = G1, G2 = G2>, M: MSMEngine<E = E>>() -> M1NoPrecomp<E, M> {
	let (g1, g2) = load_trusted_g1_g2();
	<M1NoPrecomp<_, _>>::new_from_powers(&g1, &g2)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::pmp::msm::blst::BlstMSMEngine;
	use ark_bls12_381::{Bls12_381, Fr};
	use pmp::{
		ark_poly::{
			univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
			GeneralEvaluationDomain,
		},
		traits::KZGProof,
	};
	use poly_multiproof::{ark_bls12_381, traits::Committer};
	use rand::thread_rng;

	#[test]
	fn test_public_params() {
		let pmp = couscous::multiproof_params::<Bls12_381, BlstMSMEngine>();

		let points = DensePolynomial::<Fr>::rand(1024, &mut thread_rng()).coeffs;
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

		let verify = pmp
			.verify::<BlstMSMEngine>(&pmp_commit, pmp_domain_pts[1], points[1], &proof)
			.unwrap();

		assert!(verify);
	}
}
