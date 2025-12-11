use crate::error::FriBiniusError;
use binius_verifier::config::B128;
use blake2b_simd::Params as Blake2bParams;
use core::convert::TryInto;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

const EVAL_POINT_SEED_DOMAIN: &[u8] = b"avail-fri-eval-point-seed:v1";

/// Derive a 32-byte seed from provided inputs.
fn derive_seed_from_inputs(rand_src: &[u8], blob_hash: &[u8]) -> [u8; 32] {
	let mut hasher = Blake2bParams::new().hash_length(32).to_state();
	hasher.update(EVAL_POINT_SEED_DOMAIN);
	hasher.update(rand_src);
	hasher.update(blob_hash);
	let digest = hasher.finalize();
	let bytes = digest.as_bytes();
	let mut seed = [0u8; 32];
	seed.copy_from_slice(&bytes[..32]);
	seed
}

/// Deterministically generate an evaluation point (n_vars coordinates), returning Vec<B128>.
/// - `rand_src` : arbitrary randomness (e.g. epoch randomness bytes)
/// - `blob_hash`: blob identifier (e.g. blob commitment or H256)
/// - `n_vars`   : number of coordinates (from FriParams / packed MLE)
pub fn derive_evaluation_point(rand_src: &[u8], blob_hash: &[u8], n_vars: usize) -> Vec<B128> {
	let seed = derive_seed_from_inputs(rand_src, blob_hash);
	let mut rng = ChaChaRng::from_seed(seed);

	let mut out = Vec::with_capacity(n_vars);
	let mut buf = [0u8; 16];

	for _ in 0..n_vars {
		rng.fill_bytes(&mut buf);
		let v = u128::from_le_bytes(buf);
		out.push(B128::from(v));
	}

	out
}

/// Serialize evaluation point -> bytes (concatenate 16-byte LE representations).
pub fn eval_point_to_bytes(point: &[B128]) -> Vec<u8> {
	let mut out = Vec::with_capacity(point.len() * 16);
	for p in point {
		// convert B128 -> u128; B128 likely has From<u128> and Into<u128>
		let v: u128 = (*p).into();
		out.extend_from_slice(&v.to_le_bytes());
	}
	out
}

/// Deserialize bytes -> evaluation point (expects 16*N bytes).
pub fn eval_point_from_bytes(bytes: &[u8]) -> Result<Vec<B128>, FriBiniusError> {
	if bytes.len() % 16 != 0 {
		return Err(FriBiniusError::InvalidInput(format!(
			"eval_point bytes length not multiple of 16: {}",
			bytes.len()
		)));
	}
	let n = bytes.len() / 16;
	let mut out = Vec::with_capacity(n);
	for i in 0..n {
		let chunk = &bytes[i * 16..(i + 1) * 16];
		let v = u128::from_le_bytes(chunk.try_into().unwrap());
		out.push(B128::from(v));
	}
	Ok(out)
}

/// Serialize evaluation claim (single B128) to 16 bytes.
pub fn eval_claim_to_bytes(claim: B128) -> [u8; 16] {
	let v: u128 = claim.into();
	v.to_le_bytes()
}

/// Deserialize evaluation claim from 16 bytes.
pub fn eval_claim_from_bytes(bytes: &[u8]) -> Result<B128, FriBiniusError> {
	if bytes.len() != 16 {
		return Err(FriBiniusError::InvalidInput(format!(
			"Expected 16 bytes for evaluation claim, but got {}",
			bytes.len()
		)));
	}
	let arr: [u8; 16] = bytes.try_into().expect("length checked above");
	let v = u128::from_le_bytes(arr);
	Ok(B128::from(v))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn roundtrip_eval_point_bytes() {
		let rand_src = [7u8; 32];
		let blob_hash = [11u8; 32];
		let n = 10;
		let p = derive_evaluation_point(&rand_src, &blob_hash, n);
		assert_eq!(p.len(), n);
		let b = eval_point_to_bytes(&p);
		let p2 = eval_point_from_bytes(&b).unwrap();
		assert_eq!(p.len(), p2.len());
		for (a, c) in p.into_iter().zip(p2.into_iter()) {
			assert_eq!(u128::from(a), u128::from(c));
		}
	}

	#[test]
	fn claim_serialize_roundtrip() {
		let mut rng = ChaChaRng::from_seed([1u8; 32]);
		let mut buf = [0u8; 16];
		rng.fill_bytes(&mut buf);
		let val = u128::from_le_bytes(buf);
		let claim = B128::from(val);
		let bytes = eval_claim_to_bytes(claim);
		let claim2 = eval_claim_from_bytes(&bytes).unwrap();
		assert_eq!(u128::from(claim), u128::from(claim2));
	}
}
