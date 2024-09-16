use super::super::kate::v3::KateCommitment;
use super::HeaderVersion;
use crate::sp_std::{vec, vec::Vec};
use crate::DataLookup;
use codec::{Decode, Encode};
use sp_core::H256;

#[cfg(feature = "runtime")]
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use sp_core::RuntimeDebug;
#[cfg(feature = "runtime")]
use sp_runtime_interface::pass_by::PassByCodec;

/// Header extension data.
#[derive(PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(PassByCodec, RuntimeDebug, TypeInfo))]
#[repr(u8)]
pub enum HeaderExtension {
	V3(v3::HeaderExtension) = 2,
}
impl HeaderExtension {
	pub fn data_root(&self) -> H256 {
		match self {
			HeaderExtension::V3(x) => x.data_root(),
		}
	}

	pub fn app_lookup(&self) -> &DataLookup {
		match self {
			HeaderExtension::V3(x) => &x.app_lookup,
		}
	}

	pub fn rows(&self) -> u16 {
		match self {
			HeaderExtension::V3(x) => x.rows(),
		}
	}

	pub fn cols(&self) -> u16 {
		match self {
			HeaderExtension::V3(x) => x.cols(),
		}
	}
}
impl HeaderExtension {
	#[cfg(feature = "runtime")]
	pub fn get_empty_header(data_root: H256, version: HeaderVersion) -> HeaderExtension {
		match version {
			HeaderVersion::V3 => v3::HeaderExtension::get_empty_header(data_root).into(),
		}
	}

	#[cfg(feature = "runtime")]
	pub fn get_faulty_header(data_root: H256, version: HeaderVersion) -> HeaderExtension {
		match version {
			HeaderVersion::V3 => v3::HeaderExtension::get_faulty_header(data_root).into(),
		}
	}

	#[cfg(feature = "runtime")]
	pub fn get_header_version(&self) -> HeaderVersion {
		match self {
			HeaderExtension::V3(_) => HeaderVersion::V3,
		}
	}
}

impl Default for HeaderExtension {
	fn default() -> Self {
		v3::HeaderExtension::default().into()
	}
}

impl From<v3::HeaderExtension> for HeaderExtension {
	#[inline]
	fn from(ext: v3::HeaderExtension) -> Self {
		Self::V3(ext)
	}
}

pub mod v3 {
	use super::*;

	#[derive(Clone, Encode, Decode, PartialEq, Eq, Default)]
	#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
	#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
	#[cfg_attr(feature = "runtime", derive(RuntimeDebug, TypeInfo))]
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
}
