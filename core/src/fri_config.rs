use codec::{Decode, Encode};
use scale_info::TypeInfo;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use sp_debug_derive::RuntimeDebug;
/// Parameters that Avail config / node code will set.
#[derive(Clone, Copy, Debug)]
pub struct FriParamsConfig {
	/// log2(1 / Reed–Solomon code rate).
	pub log_inv_rate: usize,
	/// Number of FRI test queries (soundness parameter).
	pub num_test_queries: usize,
	/// log2(number of “shares” / repetitions).
	pub log_num_shares: usize,
	/// Number of multilinear variables (depends on data size).
	pub n_vars: usize,
}

/// Version of Fri/Binius parameters used to interpret size_bytes into
/// codeword length and sampling domain.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, Default, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
pub struct FriParamsVersion(pub u8);

impl FriParamsVersion {
	/// Map this version to a FriParamsConfig, given `n_vars`
	pub fn to_config(self, n_vars: usize) -> FriParamsConfig {
		match self.0 {
			0 => FriParamsConfig {
				log_inv_rate: 1,
				num_test_queries: 128,
				log_num_shares: 80,
				n_vars,
			},
			_ => panic!("Unsupported FriParamsVersion {}", self.0),
		}
	}
}
