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

/// DA commitment extension — input to LC sampling & verification.
/// Replaces KZG’s KateCommitment format.
#[derive(Clone, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, Default, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
pub struct HeaderExtension {
	/// All blob commitments in canonical block order.
	pub blobs: Vec<FriBlobCommitment>,

	/// Dataroot to be used for bridge & blob inclusion proofs
	pub data_root: H256,

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
			..Default::default()
		}
	}

	pub fn get_faulty_header(data_root: H256) -> Self {
		// TODO: Differentiate b/w empty & faulty_header
		HeaderExtension {
			data_root,
			..Default::default()
		}
	}
}
