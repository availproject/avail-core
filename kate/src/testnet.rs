#![deny(clippy::arithmetic_side_effects)]

/// TODO
///  - Dedup this from `kate-recovery` once that library support `no-std`.
// use avail_core::BlockLengthColumns;
// use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
use hex_literal::hex;
// use once_cell::sync::Lazy;
use poly_multiproof::ark_ff::{BigInt, Fp};
use poly_multiproof::ark_serialize::CanonicalDeserialize;
use poly_multiproof::m1_blst;
use poly_multiproof::m1_blst::{Fr, G1, G2};
// use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
// use std::{collections::HashMap, sync::Mutex};

// static SRS_DATA: Lazy<Mutex<HashMap<u32, PublicParameters>>> =
// 	Lazy::new(|| Mutex::new(HashMap::new()));

// /// constructs public parameters for a given degree
// pub fn public_params(max_degree: BlockLengthColumns) -> PublicParameters {
// 	let max_degree: u32 = max_degree.into();
// 	let mut srs_data_locked = SRS_DATA.lock().unwrap();
// 	srs_data_locked
// 		.entry(max_degree)
// 		.or_insert_with(|| {
// 			let mut rng = ChaChaRng::seed_from_u64(42);
// 			let max_degree = usize::try_from(max_degree).unwrap();
// 			PublicParameters::setup(max_degree, &mut rng).unwrap()
// 		})
// 		.clone()
// }

const SEC_LIMBS: [u64; 4] = [
	16526363067508752668,
	17870878028964021343,
	15693365399533249662,
	1020900941429372507,
];
const G1_BYTES: [u8; 48] = hex!("a45f754a9e94cccbb2cbe9d7c441b8b527026ef05e2a3aff4aa4bb1c57df3767fb669cc4c7639bd37e683653bdc50b5a");
const G2_BYTES: [u8; 96] = hex!("b845ac5e7b4ec8541d012660276772e001c1e0475e60971884481d43fcbd44de2a02e9862dbf9f536c211814f6cc5448100bcda5dc707854af8e3829750d1fb18b127286aaa4fc959e732e2128a8a315f2f8f419bf5774fe043af46fbbeb4b27");

pub fn multiproof_params(max_degree: usize, max_pts: usize) -> m1_blst::M1NoPrecomp {
	let x: Fr = Fp(BigInt(SEC_LIMBS), core::marker::PhantomData);

	let g1 = G1::deserialize_compressed(&G1_BYTES[..]).unwrap();
	let g2 = G2::deserialize_compressed(&G2_BYTES[..]).unwrap();

	m1_blst::M1NoPrecomp::new_from_scalar(x, g1, g2, max_degree.saturating_add(1), max_pts)
}

// #[cfg(test)]
// mod tests {
// 	use core::marker::PhantomData;

// 	use super::*;
// 	use dusk_bytes::Serializable;
// 	use dusk_plonk::{
// 		fft::{EvaluationDomain as PlonkED, Evaluations as PlonkEV},
// 		prelude::BlsScalar,
// 	};
// 	use poly_multiproof::{
// 		ark_ff::{BigInt, Fp},
// 		ark_poly::{EvaluationDomain, GeneralEvaluationDomain},
// 		ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
// 		m1_blst::Fr,
// 		traits::Committer,
// 	};
// 	use rand::thread_rng;

// 	use crate::testnet;
// 	#[test]
// 	fn test_consistent_testnet_params() {
// 		let x: Fr = Fp(BigInt(SEC_LIMBS), core::marker::PhantomData);
// 		let mut out = [0u8; 32];
// 		x.serialize_compressed(&mut out[..]).unwrap();
// 		const SEC_BYTES: [u8; 32] =
// 			hex!("7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a");
// 		assert_eq!(SEC_BYTES, out);

// 		let g1 = G1::deserialize_compressed(&G1_BYTES[..]).unwrap();
// 		let g2 = G2::deserialize_compressed(&G2_BYTES[..]).unwrap();

// 		let pmp = poly_multiproof::m1_blst::M1NoPrecomp::new_from_scalar(x, g1, g2, 1024, 256);

// 		let dp_evals = (0..30)
// 			.map(|_| BlsScalar::random(&mut thread_rng()))
// 			.collect::<Vec<_>>();

// 		let pmp_evals = dp_evals
// 			.iter()
// 			.map(|i| Fp(BigInt(i.0), PhantomData))
// 			.collect::<Vec<Fr>>();

// 		let dp_poly =
// 			PlonkEV::from_vec_and_domain(dp_evals, PlonkED::new(1024).unwrap()).interpolate();
// 		let pmp_ev = GeneralEvaluationDomain::<Fr>::new(1024).unwrap();
// 		let pmp_poly = pmp_ev.ifft(&pmp_evals);

// 		let pubs = testnet::public_params(BlockLengthColumns(1024));

// 		let dp_commit = pubs.commit_key().commit(&dp_poly).unwrap().0.to_bytes();
// 		let mut pmp_commit = [0u8; 48];
// 		pmp.commit(pmp_poly)
// 			.unwrap()
// 			.0
// 			.serialize_compressed(&mut pmp_commit[..])
// 			.unwrap();

// 		assert_eq!(dp_commit, pmp_commit);
// 	}
// }
