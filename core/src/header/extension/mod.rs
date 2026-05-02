use codec::{Decode, DecodeWithMemTracking, Encode};
use primitive_types::H256;
use scale_info::TypeInfo;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use sp_debug_derive::RuntimeDebug;

pub mod fri_v1;

/// Versioned DA header extension.
///
/// The commitment scheme is FRI-only from Infinity onward. This enum is for
/// header format evolution, not scheme selection.
#[derive(PartialEq, Eq, Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
#[cfg_attr(not(feature = "runtime"), derive(Debug))]
pub enum HeaderExtension {
	V1(fri_v1::HeaderExtension),
}

impl HeaderExtension {
	pub fn data_root(&self) -> H256 {
		match self {
			HeaderExtension::V1(ext) => ext.data_root(),
		}
	}

	/// Returns true if this header commits to at least one DA blob.
	///
	/// - `false` ⇒ block contains no DA transactions
	/// - `true`  ⇒ DA commitments must be verified
	pub fn has_da_commitments(&self) -> bool {
		match self {
			HeaderExtension::V1(ext) => ext.has_da_commitments(),
		}
	}

	pub fn get_empty_header(data_root: H256) -> Self {
		HeaderExtension::V1(fri_v1::HeaderExtension::get_empty_header(data_root))
	}

	pub fn get_faulty_header(data_root: H256) -> Self {
		HeaderExtension::V1(fri_v1::HeaderExtension::get_faulty_header(data_root))
	}
}

impl Default for HeaderExtension {
	fn default() -> Self {
		HeaderExtension::V1(fri_v1::HeaderExtension::default())
	}
}

impl From<fri_v1::HeaderExtension> for HeaderExtension {
	fn from(ext: fri_v1::HeaderExtension) -> Self {
		HeaderExtension::V1(ext)
	}
}
