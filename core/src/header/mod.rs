// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Data-Avail implementation of a block header.

use crate::from_substrate::HexDisplay;
use crate::traits::ExtendedHeader;
use codec::{Decode, DecodeWithMemTracking, Encode};
use primitive_types::U256;
use sp_std::{
	convert::TryFrom,
	fmt::{Debug, Formatter},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use {
	scale_info::TypeInfo,
	sp_runtime::{
		traits::{BlockNumber, Hash as HashT, Header as HeaderT},
		Digest,
	},
};

#[cfg(feature = "std")]
const LOG_TARGET: &str = "header";

pub mod extension;
pub use extension::HeaderExtension;

/// Abstraction over a block header for a substrate chain.
#[derive(PartialEq, Eq, Clone, TypeInfo, Encode, Decode, DecodeWithMemTracking)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
	feature = "serde",
	serde(deny_unknown_fields, rename_all = "camelCase")
)]
pub struct Header<N, H>
where
	N: BlockNumber,
	H: HashT,
	H::Output: TypeInfo,
{
	/// The parent hash.
	pub parent_hash: H::Output,
	/// The block number.
	#[cfg_attr(feature = "serde", serde(with = "number_serde"))]
	#[codec(compact)]
	pub number: N,
	/// The state trie merkle root
	pub state_root: H::Output,
	/// The merkle root of the extrinsics.
	pub extrinsics_root: H::Output,
	/// A chain-specific digest of data useful for light clients or referencing auxiliary data.
	pub digest: Digest,
	/// Data Availability header extension.
	pub extension: HeaderExtension,
}

impl<N, H> Header<N, H>
where
	N: BlockNumber,
	H: HashT,
	H::Output: TypeInfo,
{
	/// Creates a header V1
	#[inline]
	pub fn new(
		number: N,
		extrinsics_root: H::Output,
		state_root: H::Output,
		parent_hash: H::Output,
		digest: Digest,
		extension: HeaderExtension,
	) -> Self {
		Self {
			parent_hash,
			number,
			state_root,
			extrinsics_root,
			digest,
			extension,
		}
	}

	/// Convenience helper for computing the hash of the header without having
	/// to import the trait.
	#[inline]
	pub fn hash(&self) -> H::Output {
		H::hash_of(self)
	}
}

impl<N, H> Debug for Header<N, H>
where
	N: BlockNumber,
	H: HashT,
	H::Output: TypeInfo,
{
	fn fmt(&self, f: &mut Formatter<'_>) -> sp_std::fmt::Result {
		let parent_hash = self.parent_hash.as_ref();
		let state_root = self.state_root.as_ref();
		let extrinsics_root = self.extrinsics_root.as_ref();

		f.debug_struct("Header")
			.field("parent_hash", &HexDisplay(parent_hash))
			.field("number", &self.number)
			.field("state_root", &HexDisplay(state_root))
			.field("extrinsics_root", &HexDisplay(extrinsics_root))
			.field("digest", &self.digest)
			.field("extension", &self.extension)
			.finish()
	}
}

/// This module adds serialization support to `Header::number` field.
#[cfg(feature = "serde")]
mod number_serde {
	use serde::{de::Error, Deserializer, Serializer};

	use super::*;

	pub fn serialize<N, S>(n: &N, serializer: S) -> Result<S::Ok, S::Error>
	where
		N: BlockNumber,
		S: Serializer,
	{
		let u256: U256 = (*n).into();
		serde::Serialize::serialize(&u256, serializer)
	}

	pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
	where
		T: BlockNumber,
		D: Deserializer<'de>,
	{
		let u256: U256 = serde::Deserialize::deserialize(d)?;
		TryFrom::try_from(u256).map_err(|_| Error::custom("Try from failed"))
	}
}

impl<N, H> Default for Header<N, H>
where
	N: BlockNumber,
	H: HashT,
	H::Output: TypeInfo,
{
	fn default() -> Self {
		Self {
			parent_hash: Default::default(),
			number: Default::default(),
			state_root: Default::default(),
			extrinsics_root: Default::default(),
			digest: Default::default(),
			extension: Default::default(),
		}
	}
}

impl<N, H> HeaderT for Header<N, H>
where
	N: BlockNumber,
	H: HashT,
	H::Output: TypeInfo,
	Header<N, H>: TypeInfo,
{
	type Hash = H::Output;
	type Hashing = H;
	type Number = N;

	fn number(&self) -> &Self::Number {
		&self.number
	}

	fn set_number(&mut self, num: Self::Number) {
		self.number = num
	}

	fn extrinsics_root(&self) -> &Self::Hash {
		&self.extrinsics_root
	}

	fn set_extrinsics_root(&mut self, root: Self::Hash) {
		self.extrinsics_root = root
	}

	fn state_root(&self) -> &Self::Hash {
		&self.state_root
	}

	fn set_state_root(&mut self, root: Self::Hash) {
		self.state_root = root
	}

	fn parent_hash(&self) -> &Self::Hash {
		&self.parent_hash
	}

	fn set_parent_hash(&mut self, hash: Self::Hash) {
		self.parent_hash = hash
	}

	fn digest(&self) -> &Digest {
		&self.digest
	}

	fn digest_mut(&mut self) -> &mut Digest {
		#[cfg(feature = "std")]
		log::debug!(target: LOG_TARGET, "Retrieving mutable reference to digest");
		&mut self.digest
	}

	fn new(
		number: Self::Number,
		extrinsics_root: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
	) -> Self {
		Self {
			number,
			parent_hash,
			state_root,
			digest,
			extrinsics_root,
			extension: Default::default(),
		}
	}
}

impl<N, H> ExtendedHeader for Header<N, H>
where
	N: BlockNumber,
	H: HashT,
	H::Output: TypeInfo,
	Header<N, H>: HeaderT<Hashing = H, Hash = H::Output, Number = N>,
{
	type Extension = HeaderExtension;

	/// Creates new header.
	fn new(
		n: Self::Number,
		extrinsics: H::Output,
		state: H::Output,
		parent: H::Output,
		digest: Digest,
		extension: HeaderExtension,
	) -> Self {
		Header::<N, H>::new(n, extrinsics, state, parent, digest, extension)
	}

	fn extension(&self) -> &HeaderExtension {
		&self.extension
	}

	fn set_extension(&mut self, extension: HeaderExtension) {
		self.extension = extension;
	}
}
