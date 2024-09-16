//! Generic implementation of a DA block and associated items.

use super::header::Header;
use crate::sp_std::prelude::*;
use avail_core_substrate::Justifications;
use codec::{Codec, Decode, Encode};

#[cfg(feature = "runtime")]
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use sp_debug_derive::RuntimeDebug;

/// Abstraction over a substrate block.
#[derive(PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[cfg_attr(feature = "runtime", derive(TypeInfo, RuntimeDebug))]
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
#[derive(PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]

pub struct SignedBlock<Block: Codec> {
	/// Full block.
	pub block: Block,
	/// Block justification.
	pub justifications: Option<Justifications>,
}
