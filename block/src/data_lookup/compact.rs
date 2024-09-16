use super::DataLookup;

use crate::sp_std::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Encode, Decode, TypeInfo, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DataLookupItem {
	pub app_id: u32,
	#[codec(compact)]
	pub start: u32,
}

impl DataLookupItem {
	pub fn new(app_id: u32, start: u32) -> Self {
		Self { app_id, start }
	}
}

impl From<(u32, u32)> for DataLookupItem {
	fn from(value: (u32, u32)) -> Self {
		Self {
			app_id: value.0,
			start: value.1,
		}
	}
}

// If .size is 0, and index contains items then no commitment was generated
// because of an error that occurred.
//
// This is just a temporary solution that will be replaced by a more
// sofisticated one once we do to do the next header change.
//
#[derive(Encode, Decode, TypeInfo, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompactDataLookup {
	/// size of the look up
	#[codec(compact)]
	pub(crate) size: u32,
	/// sorted vector of tuples(key, start index)
	pub(crate) index: Vec<DataLookupItem>,
}

impl CompactDataLookup {
	pub fn new(size: u32, index: Vec<DataLookupItem>) -> Self {
		Self { size, index }
	}

	pub fn is_error(&self) -> bool {
		// For backward compatibility, case when size is u32::MAX is also supported
		self.size == u32::MAX || (self.size == 0 && !self.index.is_empty())
	}

	// Data lookup is not valid if size is 0 and lookup index is not empty
	fn new_error() -> Self {
		Self {
			size: 0,
			index: [DataLookupItem::new(0, 0)].to_vec(),
		}
	}

	pub fn from_data_lookup(lookup: &DataLookup) -> Self {
		if lookup.is_error() {
			return Self::new_error();
		}

		let index = lookup
			.index
			.iter()
			.filter(|(id, _)| *id != 0)
			.map(|(id, range)| DataLookupItem::new(*id, range.start))
			.collect();
		let size = lookup.index.last().map_or(0, |(_, range)| range.end);
		Self { size, index }
	}
}

// We added this just to please the compiler regarding the Serde macro.
// Do not change this implementation!
//
impl From<DataLookup> for CompactDataLookup {
	fn from(lookup: DataLookup) -> Self {
		Self::from_data_lookup(&lookup)
	}
}
