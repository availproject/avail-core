use codec::{Decode, Encode};
use primitive_types::H256;
use scale_info::TypeInfo;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use {sp_debug_derive::RuntimeDebug, sp_runtime_interface::pass_by::PassByCodec};

pub mod fri_v1;
// basically only supported kzg header currently
pub mod v4;

pub mod kzg {
	use super::*;

	/// Versioning for KZG header formats.
	#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo)]
	#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
	#[cfg_attr(feature = "runtime", derive(PassByCodec, RuntimeDebug))]
	pub enum KzgHeaderVersion {
		V4,
	}

	#[derive(PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
	#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
	#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
	#[cfg_attr(not(feature = "runtime"), derive(Debug))]
	pub enum KzgHeader {
		V4(v4::HeaderExtension),
	}

	impl KzgHeader {
		pub fn data_root(&self) -> H256 {
			match self {
				KzgHeader::V4(ext) => ext.data_root(),
			}
		}

		pub fn version(&self) -> KzgHeaderVersion {
			match self {
				KzgHeader::V4(_) => KzgHeaderVersion::V4,
			}
		}

		/// Returns true if this header commits to at least one DA blob.
		pub fn has_da_commitments(&self) -> bool {
			match self {
				KzgHeader::V4(ext) => !ext.commitment.commitment.is_empty(),
			}
		}

		pub fn get_empty_header(data_root: H256, version: KzgHeaderVersion) -> Self {
			match version {
				KzgHeaderVersion::V4 => v4::HeaderExtension::get_empty_header(data_root).into(),
			}
		}

		pub fn get_faulty_header(data_root: H256, version: KzgHeaderVersion) -> Self {
			match version {
				KzgHeaderVersion::V4 => v4::HeaderExtension::get_faulty_header(data_root).into(),
			}
		}
	}

	impl From<v4::HeaderExtension> for KzgHeader {
		#[inline]
		fn from(ext: v4::HeaderExtension) -> Self {
			KzgHeader::V4(ext)
		}
	}
}

pub mod fri {
	use super::*;

	/// Versioning for Fri/Binius header formats.
	#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo)]
	#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
	#[cfg_attr(feature = "runtime", derive(PassByCodec, RuntimeDebug))]
	pub enum FriHeaderVersion {
		V1,
	}

	#[derive(PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
	#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
	#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
	#[cfg_attr(not(feature = "runtime"), derive(Debug))]
	pub enum FriHeader {
		V1(fri_v1::HeaderExtension),
	}

	impl FriHeader {
		pub fn data_root(&self) -> H256 {
			match self {
				FriHeader::V1(ext) => ext.data_root(),
			}
		}

		pub fn version(&self) -> FriHeaderVersion {
			match self {
				FriHeader::V1(_) => FriHeaderVersion::V1,
			}
		}

		/// Returns true if this header commits to at least one DA blob.
		pub fn has_da_commitments(&self) -> bool {
			match self {
				FriHeader::V1(ext) => !ext.blobs.is_empty(),
			}
		}

		pub fn get_empty_header(data_root: H256, version: FriHeaderVersion) -> Self {
			match version {
				FriHeaderVersion::V1 => fri_v1::HeaderExtension::get_empty_header(data_root).into(),
			}
		}

		pub fn get_faulty_header(data_root: H256, version: FriHeaderVersion) -> Self {
			match version {
				FriHeaderVersion::V1 => {
					fri_v1::HeaderExtension::get_faulty_header(data_root).into()
				},
			}
		}
	}

	impl From<fri_v1::HeaderExtension> for FriHeader {
		#[inline]
		fn from(ext: fri_v1::HeaderExtension) -> Self {
			FriHeader::V1(ext)
		}
	}
}

#[derive(Clone, Copy, Eq, PartialEq, Debug, Encode, Decode, TypeInfo)]
pub enum CommitmentScheme {
	Kzg,
	Fri,
}

/// header extension: *which PCS + which version inside*.
#[derive(PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(PassByCodec, RuntimeDebug))]
#[cfg_attr(not(feature = "runtime"), derive(Debug))]
pub enum HeaderExtension {
	Kzg(kzg::KzgHeader),
	Fri(fri::FriHeader),
}

impl HeaderExtension {
	pub fn data_root(&self) -> H256 {
		match self {
			HeaderExtension::Kzg(h) => h.data_root(),
			HeaderExtension::Fri(h) => h.data_root(),
		}
	}

	pub fn is_kzg(&self) -> bool {
		matches!(self, HeaderExtension::Kzg(_))
	}

	pub fn is_fri(&self) -> bool {
		matches!(self, HeaderExtension::Fri(_))
	}

	/// Returns true if this header commits to at least one DA blob.
	///
	/// - `false` ⇒ block contains no DA transactions
	/// - `true`  ⇒ DA commitments must be verified
	pub fn has_da_commitments(&self) -> bool {
		match self {
			HeaderExtension::Kzg(h) => h.has_da_commitments(),
			HeaderExtension::Fri(h) => h.has_da_commitments(),
		}
	}

	pub fn commitment_scheme(&self) -> CommitmentScheme {
		match self {
			HeaderExtension::Fri(_) => CommitmentScheme::Fri,
			HeaderExtension::Kzg(_) => CommitmentScheme::Kzg,
		}
	}

	pub fn get_empty_kzg(data_root: H256, version: kzg::KzgHeaderVersion) -> Self {
		HeaderExtension::Kzg(kzg::KzgHeader::get_empty_header(data_root, version))
	}

	pub fn get_empty_fri(data_root: H256, version: fri::FriHeaderVersion) -> Self {
		HeaderExtension::Fri(fri::FriHeader::get_empty_header(data_root, version))
	}

	pub fn get_faulty_kzg(data_root: H256, version: kzg::KzgHeaderVersion) -> Self {
		HeaderExtension::Kzg(kzg::KzgHeader::get_faulty_header(data_root, version))
	}

	pub fn get_faulty_fri(data_root: H256, version: fri::FriHeaderVersion) -> Self {
		HeaderExtension::Fri(fri::FriHeader::get_faulty_header(data_root, version))
	}
}

impl Default for HeaderExtension {
	fn default() -> Self {
		HeaderExtension::Fri(fri::FriHeader::V1(fri_v1::HeaderExtension::default()))
	}
}
