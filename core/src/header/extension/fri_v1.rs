use crate::FriParamsVersion;
use codec::{Decode, DecodeWithMemTracking, Encode};
use primitive_types::H256;
use scale_info::TypeInfo;
use sp_std::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use sp_debug_derive::RuntimeDebug;

/// Metadata needed for DA sampling + PCS verification of one blob.
#[derive(Clone, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, Default, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
pub struct FriBlobCommitment {
	/// Blob hash
	pub blob_hash: H256,
	/// Original blob size in bytes.
	pub size_bytes: u64,

	/// Fri PCS commitment (Merkle root of the blob codeword).
	pub commitment: Vec<u8>,
}

/// DA commitment extension — concise header view for FRI/Binius.
///
/// Per-blob commitments live in the sidecar; the header only commits to them
/// via aggregate metadata and the data root.
#[derive(Clone, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, Default, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
pub struct HeaderExtension {
	/// Number of DA blobs in this block.
	pub blob_count: u32,

	/// Dataroot to be used for bridge & blob inclusion proofs
	pub data_root: H256,

	/// Merkle root over per-blob metadata.
	pub blob_meta_root: H256,

	/// Parameter set identifier to decode sampling domain / FRI params.
	pub params_version: FriParamsVersion,
}

impl HeaderExtension {
	pub fn data_root(&self) -> H256 {
		self.data_root
	}

	pub fn get_empty_header(data_root: H256) -> Self {
		HeaderExtension {
			data_root,
			blob_meta_root: H256::zero(),
			blob_count: 0,
			..Default::default()
		}
	}

	pub fn get_faulty_header(data_root: H256) -> Self {
		HeaderExtension {
			data_root,
			blob_meta_root: H256::zero(),
			blob_count: 0,
			..Default::default()
		}
	}
}
