use sha3::Digest;

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

/// Do a Blake2 128-bit hash and return result.
pub fn blake2_128(data: &[u8]) -> [u8; 16] {
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

pub struct HexDisplay<'a>(pub &'a [u8]);

impl<'a> sp_std::fmt::Display for HexDisplay<'a> {
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> Result<(), sp_std::fmt::Error> {
		let len = self.0.len();
		if len < 1027 {
			for byte in self.0 {
				f.write_fmt(format_args!("{:02x}", byte))?;
			}
		} else {
			for byte in &self.0[0..512] {
				f.write_fmt(format_args!("{:02x}", byte))?;
			}
			f.write_str("...")?;
			let start = len.saturating_sub(512);
			for byte in &self.0[start..] {
				f.write_fmt(format_args!("{:02x}", byte))?;
			}
		}
		Ok(())
	}
}

impl<'a> sp_std::fmt::Debug for HexDisplay<'a> {
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> Result<(), sp_std::fmt::Error> {
		for byte in self.0 {
			f.write_fmt(format_args!("{:02x}", byte))?;
		}
		Ok(())
	}
}
