//! Generic implementation of a DA block and associated items.

use super::header::Header;
use crate::sp_std::prelude::*;
use codec::{Codec, Decode, Encode};
use sp_core::RuntimeDebug;
use sp_runtime::Justifications;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Abstraction over a substrate block.
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct DaBlock<Extrinsic>
where
	Extrinsic: Codec,
{
	/// The block header.
	pub header: Header,
	/// The accompanying extrinsics.
	pub extrinsics: Vec<Extrinsic>,
}

/// Abstraction over a substrate block and justification.
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct SignedBlock<Block: Codec> {
	/// Full block.
	pub block: Block,
	/// Block justification.
	pub justifications: Option<Justifications>,
}
