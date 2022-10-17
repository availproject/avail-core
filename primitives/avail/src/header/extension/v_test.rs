use codec::{Decode, Encode};
#[cfg(feature = "std")]
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;

use crate::{asdr::DataLookup, KateCommitment};

#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo, Encode, Decode, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct HeaderExtension {
	pub new_field: Vec<u8>,
	pub commitment: KateCommitment,
	pub app_data_lookup: DataLookup,
}

#[cfg(feature = "std")]
impl MallocSizeOf for HeaderExtension {
	fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
		self.new_field.size_of(ops)
			+ self.commitment.size_of(ops)
			+ self.app_data_lookup.size_of(ops)
	}
}
