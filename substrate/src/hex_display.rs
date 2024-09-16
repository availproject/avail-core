use crate::sp_std;

pub struct HexDisplay<'a>(pub &'a [u8]);

impl<'a> sp_std::fmt::Display for HexDisplay<'a> {
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> Result<(), sp_std::fmt::Error> {
		if self.0.len() < 1027 {
			for byte in self.0 {
				f.write_fmt(format_args!("{:02x}", byte))?;
			}
		} else {
			for byte in &self.0[0..512] {
				f.write_fmt(format_args!("{:02x}", byte))?;
			}
			f.write_str("...")?;
			for byte in &self.0[self.0.len() - 512..] {
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
