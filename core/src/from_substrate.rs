use sha3::Digest;

////////////// START SP-IO
#[inline(always)]
fn blake2<const N: usize>(data: &[u8]) -> [u8; N] {
	blake2b_simd::Params::new()
		.hash_length(N)
		.hash(data)
		.as_bytes()
		.try_into()
		.expect("slice is always the necessary length")
}

/// Do a Blake2 256-bit hash and return result.
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
	blake2(data)
}

/// Do a keccak 256-bit hash and return result.
pub fn keccak_256(data: &[u8]) -> [u8; 32] {
	sha3::Keccak256::digest(data).into()
}

/// Do a sha2 256-bit hash and return result.
pub fn sha2_256(data: &[u8]) -> [u8; 32] {
	sha2::Sha256::digest(data).into()
}

////////////// END SP-IO
