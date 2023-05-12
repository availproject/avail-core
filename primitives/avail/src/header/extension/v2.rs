use codec::{Decode, Encode};
#[cfg(feature = "std")]
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::{RuntimeDebug, H256};

use crate::{asdr::DataLookup, v2::KateCommitment};

#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo, Encode, Decode, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct HeaderExtension {
	pub app_lookup: DataLookup,
	pub commitment: KateCommitment,
	data_root: Option<H256>,
}

impl HeaderExtension {
	pub fn new(commitment: KateCommitment, app_lookup: DataLookup, data_root: H256) -> Self {
		let data_root = (!data_root.is_zero()).then_some(data_root);
		Self {
			commitment,
			app_lookup,
			data_root,
		}
	}

	pub fn data_root(&self) -> H256 {
		self.data_root.unwrap_or_default()
	}

	pub fn app_lookup(&self) -> &DataLookup {
		&self.app_lookup
	}
}

#[cfg(feature = "std")]
impl MallocSizeOf for HeaderExtension {
	fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
		self.commitment.size_of(ops) + self.app_lookup.size_of(ops)
	}
}
