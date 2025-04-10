#![deny(clippy::arithmetic_side_effects)]

use dusk_plonk::commitment_scheme::kzg10::PublicParameters;

// TODO: load pp for both dusk & arkworks from same file
// To be used for incentivised testnet
use core::convert::TryInto;
use poly_multiproof::ark_serialize::CanonicalDeserialize;
use poly_multiproof::m1_blst;
use poly_multiproof::m1_blst::{G1, G2};
use sp_std::vec::Vec;

/// Constructs public parameters from pre-generated points for degree upto 1024
pub fn public_params() -> PublicParameters {
	// We can also use the raw data to make deserilization faster at the cost of size of the data
	let pp_bytes = include_bytes!("pp_1024.data");
	PublicParameters::from_slice(pp_bytes).expect("Deserialization should work")
}

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
	use dusk_plonk::{
		commitment_scheme::kzg10::proof::Proof,
		fft::{EvaluationDomain as DPEvaluationDomain, Evaluations},
	};
	use kate_recovery::{data::Cell, matrix::Position};
	use pmp::{
		ark_poly::{
			univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
			GeneralEvaluationDomain,
		},
		traits::KZGProof,
	};
	use poly_multiproof::{
		m1_blst::Fr,
		traits::{AsBytes, Committer},
	};
	use rand::thread_rng;

	#[test]
	fn test_consistent_testnet_params() {
		use dusk_bytes::Serializable;
		use dusk_plonk::prelude::BlsScalar;

		let pmp = multiproof_params();
		let pmp2 = public_params();

		let points = DensePolynomial::<Fr>::rand(1023, &mut thread_rng()).coeffs;
		let points2: Vec<_> = points
			.iter()
			.map(|p| BlsScalar::from_bytes(&p.to_bytes().unwrap()).unwrap())
			.collect();

		let dp_ev = DPEvaluationDomain::new(1024).unwrap();
		let dp_poly = Evaluations::from_vec_and_domain(points2.clone(), dp_ev).interpolate();
		let dp_domain_pts = dp_ev.elements().collect::<Vec<_>>();
		let pmp_ev = GeneralEvaluationDomain::<Fr>::new(1024).unwrap();
		let pmp_poly = pmp_ev.ifft(&points);
		let pmp_domain_pts = pmp_ev.elements().collect::<Vec<_>>();

		let dp_commit = pmp2.commit_key().commit(&dp_poly).unwrap();
		let pmp_commit = pmp.commit(&pmp_poly).unwrap();

		assert_eq!(dp_commit.0.to_bytes(), pmp_commit.to_bytes().unwrap());

		let proof = pmp
			.open(
				pmp.compute_witness_polynomial(pmp_poly, pmp_domain_pts[1])
					.unwrap(),
			)
			.unwrap();

		let proof2 = pmp2
			.commit_key()
			.commit(
				&pmp2
					.commit_key()
					.compute_single_witness(&dp_poly, &dp_domain_pts[1]),
			)
			.unwrap();

		assert_eq!(proof.to_bytes().unwrap(), proof2.to_bytes());

		let verify1 = pmp
			.verify(&pmp_commit, pmp_domain_pts[1], points[1], &proof)
			.unwrap();

		let dp_proof_obj = Proof {
			commitment_to_witness: proof2,
			evaluated_point: points2[1],
			commitment_to_polynomial: dp_commit,
		};
		assert!(pmp2.opening_key().check(dp_domain_pts[1], dp_proof_obj));

		let mut content = [0u8; 80];
		content[..48].copy_from_slice(&proof2.to_bytes());
		content[48..].copy_from_slice(&points2[1].to_bytes());
		let verify2 = kate_recovery::proof::verify(
			&pmp2,
			Dimensions::new(1, 1024).unwrap(),
			&dp_commit.0.to_bytes(),
			&Cell {
				content,
				position: Position { row: 0, col: 1 },
			},
		)
		.unwrap();

		assert!(verify1);
		assert!(verify2);
	}
}

// vim: set noet nowrap
