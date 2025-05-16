#![deny(clippy::arithmetic_side_effects)]

use super::commons::{ArkPublicParams, ArkScalar};
use hex_literal::hex;
use poly_multiproof::{
	ark_bls12_381::{G1Projective as G1, G2Projective as G2},
	ark_ff::{BigInt, Fp},
	ark_serialize::CanonicalDeserialize,
};

const SEC_LIMBS: [u64; 4] = [
	16526363067508752668,
	17870878028964021343,
	15693365399533249662,
	1020900941429372507,
];
const G1_BYTES: [u8; 48] = hex!("a45f754a9e94cccbb2cbe9d7c441b8b527026ef05e2a3aff4aa4bb1c57df3767fb669cc4c7639bd37e683653bdc50b5a");
const G2_BYTES: [u8; 96] = hex!("b845ac5e7b4ec8541d012660276772e001c1e0475e60971884481d43fcbd44de2a02e9862dbf9f536c211814f6cc5448100bcda5dc707854af8e3829750d1fb18b127286aaa4fc959e732e2128a8a315f2f8f419bf5774fe043af46fbbeb4b27");

pub fn multiproof_params(max_degree: usize, max_pts: usize) -> ArkPublicParams {
	let x: ArkScalar = Fp(BigInt(SEC_LIMBS), core::marker::PhantomData);

	let g1 = G1::deserialize_compressed(&G1_BYTES[..]).unwrap();
	let g2 = G2::deserialize_compressed(&G2_BYTES[..]).unwrap();

	ArkPublicParams::new_from_scalar(x, g1, g2, max_degree.saturating_add(1), max_pts)
}
