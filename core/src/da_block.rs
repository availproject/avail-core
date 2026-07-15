// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
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

//! Generic implementation of a DA block and associated items.

#[cfg(feature = "std")]
use std::fmt;

use crate::traits::{ExtendedBlock, ExtendedHeader};
use codec::{Codec, Decode, DecodeWithMemTracking, Encode, EncodeLike};
use sp_runtime::{
	traits::{
		self, Block as BlockT, Header as HeaderT, MaybeSerializeDeserialize, Member, NumberFor,
	},
	Justifications, OpaqueExtrinsic,
};
use sp_std::prelude::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Something to identify a block.
#[derive(PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "runtime", derive(Debug))]
pub enum BlockId<Block: BlockT> {
	/// Identify by block header hash.
	Hash(Block::Hash),
	/// Identify by block number.
	Number(NumberFor<Block>),
}

impl<Block: BlockT> BlockId<Block> {
	/// Create a block ID from a hash.
	pub const fn hash(hash: Block::Hash) -> Self {
		BlockId::Hash(hash)
	}

	/// Create a block ID from a number.
	pub const fn number(number: NumberFor<Block>) -> Self {
		BlockId::Number(number)
	}

	/// Check if this block ID refers to the pre-genesis state.
	pub fn is_pre_genesis(&self) -> bool {
		match self {
			BlockId::Hash(hash) => hash == &Default::default(),
			BlockId::Number(_) => false,
		}
	}

	/// Create a block ID for a pre-genesis state.
	pub fn pre_genesis() -> Self {
		BlockId::Hash(Default::default())
	}
}

impl<Block: BlockT> Copy for BlockId<Block> {}

#[cfg(feature = "std")]
impl<Block: BlockT> fmt::Display for BlockId<Block> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}

/// Abstraction over a substrate block.
#[derive(
	PartialEq, Eq, Clone, Encode, Decode, DecodeWithMemTracking, Debug, scale_info::TypeInfo,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct DaBlock<Header, Extrinsic>
where
	Header: Codec,
	Extrinsic: Codec,
{
	/// The block header.
	pub header: Header,
	/// The accompanying extrinsics.
	pub extrinsics: Vec<Extrinsic>,
}

/// A shadow DA block that lazily decodes its extrinsics.
#[derive(Debug, Encode, Decode, scale_info::TypeInfo)]
pub struct DaLazyBlock<Header, Extrinsic> {
	/// The block header.
	pub header: Header,
	/// The encoded extrinsics.
	pub extrinsics: Vec<OpaqueExtrinsic>,
	_phantom: core::marker::PhantomData<Extrinsic>,
}

impl<Header, Extrinsic: Into<OpaqueExtrinsic>> DaLazyBlock<Header, Extrinsic> {
	/// Creates a lazy DA block from its decoded parts.
	pub fn new(header: Header, extrinsics: Vec<Extrinsic>) -> Self {
		Self {
			header,
			extrinsics: extrinsics.into_iter().map(Into::into).collect(),
			_phantom: Default::default(),
		}
	}
}

impl<Header, Extrinsic: Codec + Into<OpaqueExtrinsic>> From<DaBlock<Header, Extrinsic>>
	for DaLazyBlock<Header, Extrinsic>
where
	Header: Codec,
{
	fn from(block: DaBlock<Header, Extrinsic>) -> Self {
		Self::new(block.header, block.extrinsics)
	}
}

impl<Header, Extrinsic> EncodeLike<DaLazyBlock<Header, Extrinsic>> for DaBlock<Header, Extrinsic>
where
	Header: Codec,
	Extrinsic: Codec,
	DaBlock<Header, Extrinsic>: Encode,
	DaLazyBlock<Header, Extrinsic>: Encode,
{
}

impl<Header, Extrinsic> EncodeLike<DaBlock<Header, Extrinsic>> for DaLazyBlock<Header, Extrinsic>
where
	Header: Codec,
	Extrinsic: Codec,
	DaBlock<Header, Extrinsic>: Encode,
	DaLazyBlock<Header, Extrinsic>: Encode,
{
}

impl<Header, Extrinsic> traits::LazyBlock for DaLazyBlock<Header, Extrinsic>
where
	Header: HeaderT,
	Extrinsic: core::fmt::Debug + traits::LazyExtrinsic,
{
	type Extrinsic = Extrinsic;
	type Header = Header;

	fn header(&self) -> &Self::Header {
		&self.header
	}

	fn header_mut(&mut self) -> &mut Self::Header {
		&mut self.header
	}

	fn extrinsics(&self) -> impl Iterator<Item = Result<Self::Extrinsic, codec::Error>> {
		self.extrinsics
			.iter()
			.map(|extrinsic| Self::Extrinsic::decode_unprefixed(extrinsic.inner()))
	}
}

impl<Header, Extrinsic> traits::HeaderProvider for DaBlock<Header, Extrinsic>
where
	Header: Codec + HeaderT,
	Extrinsic: Codec,
{
	type HeaderT = Header;
}

impl<Header, Extrinsic> BlockT for DaBlock<Header, Extrinsic>
where
	Header: Codec + HeaderT + MaybeSerializeDeserialize,
	Extrinsic: Member
		+ Codec
		+ DecodeWithMemTracking
		+ MaybeSerializeDeserialize
		+ traits::ExtrinsicLike
		+ Into<OpaqueExtrinsic>
		+ traits::LazyExtrinsic,
{
	type Extrinsic = Extrinsic;
	type Header = Header;
	type Hash = <Self::Header as traits::Header>::Hash;
	type LazyBlock = DaLazyBlock<Header, Extrinsic>;

	fn header(&self) -> &Self::Header {
		&self.header
	}
	fn extrinsics(&self) -> &[Self::Extrinsic] {
		&self.extrinsics[..]
	}
	fn deconstruct(self) -> (Self::Header, Vec<Self::Extrinsic>) {
		(self.header, self.extrinsics)
	}
	fn new(header: Self::Header, extrinsics: Vec<Self::Extrinsic>) -> Self {
		DaBlock { header, extrinsics }
	}
}

impl<Header, Extrinsic> ExtendedBlock for DaBlock<Header, Extrinsic>
where
	Header: Codec + ExtendedHeader + MaybeSerializeDeserialize,
	Extrinsic: Member
		+ Codec
		+ DecodeWithMemTracking
		+ traits::ExtrinsicLike
		+ MaybeSerializeDeserialize
		+ Into<OpaqueExtrinsic>
		+ traits::LazyExtrinsic,
{
	type ExtHeader = Header;
}

/// Abstraction over a substrate block and justification.
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct SignedBlock<Block: Codec> {
	/// Full block.
	pub block: Block,
	/// Block justification.
	pub justifications: Option<Justifications>,
}
