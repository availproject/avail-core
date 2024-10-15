use crate::{v3::KateCommitment, DataLookup};
use codec::{Decode, Encode};
use primitive_types::H256;
use sp_std::{vec, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use {scale_info::TypeInfo, sp_debug_derive::RuntimeDebug};

#[derive(PartialEq, Eq, Clone, Encode, Decode, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "runtime", derive(TypeInfo, RuntimeDebug))]
pub struct HeaderExtension {
	pub app_lookup: DataLookup,
	pub commitment: KateCommitment,
}

impl HeaderExtension {
	pub fn data_root(&self) -> H256 {
		self.commitment.data_root
	}

	pub fn app_lookup(&self) -> &DataLookup {
		&self.app_lookup
	}

	pub fn rows(&self) -> u16 {
		self.commitment.rows
	}

	pub fn cols(&self) -> u16 {
		self.commitment.cols
	}

	pub fn get_empty_header(data_root: H256) -> Self {
		let empty_commitment: Vec<u8> = vec![];
		let empty_app_lookup = DataLookup::new_empty();
		let commitment = KateCommitment::new(0, 0, data_root, empty_commitment);
		HeaderExtension {
			app_lookup: empty_app_lookup,
			commitment,
		}
	}

	pub fn get_faulty_header(data_root: H256) -> Self {
		let empty_commitment: Vec<u8> = vec![];
		let error_app_lookup = DataLookup::new_error();
		let commitment = KateCommitment::new(0, 0, data_root, empty_commitment);
		HeaderExtension {
			app_lookup: error_app_lookup,
			commitment,
		}
	}
}
