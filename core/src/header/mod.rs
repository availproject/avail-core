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
use codec::{Decode, Encode};
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
	sp_runtime_interface::pass_by::{Codec as PassByCodecImpl, PassBy},
};

#[cfg(feature = "std")]
const LOG_TARGET: &str = "header";

pub mod extension;
pub use extension::HeaderExtension;

/// Abstraction over a block header for a substrate chain.
#[derive(PartialEq, Eq, Clone, TypeInfo, Encode, Decode)]
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

#[cfg(feature = "runtime")]
impl<N, H> PassBy for Header<N, H>
where
	N: BlockNumber,
	H: HashT,
	H::Output: TypeInfo,
{
	type PassBy = PassByCodecImpl<Header<N, H>>;
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

#[cfg(all(test, feature = "runtime"))]
mod tests {
	use codec::Error;
	use hex_literal::hex;
	use primitive_types::H256;
	use sp_runtime::{traits::BlakeTwo256, DigestItem};
	use test_case::test_case;

	use super::*;
	use crate::{kate_commitment::v3, AppId, DataLookup};

	type THeader = Header<u32, BlakeTwo256>;

	#[test]
	fn should_serialize_numbers() {
		fn serialize(num: u128) -> String {
			let mut v = vec![];
			{
				let mut ser = serde_json::Serializer::new(std::io::Cursor::new(&mut v));
				number_serde::serialize(&num, &mut ser).unwrap();
			}
			String::from_utf8(v).unwrap()
		}

		assert_eq!(serialize(0), "\"0x0\"".to_owned());
		assert_eq!(serialize(1), "\"0x1\"".to_owned());
		assert_eq!(
			serialize(u64::max_value() as u128),
			"\"0xffffffffffffffff\"".to_owned()
		);
		assert_eq!(
			serialize(u64::max_value() as u128 + 1),
			"\"0x10000000000000000\"".to_owned()
		);
	}

	#[test]
	fn should_deserialize_number() {
		fn deserialize(num: &str) -> u128 {
			let mut der = serde_json::Deserializer::new(serde_json::de::StrRead::new(num));
			number_serde::deserialize(&mut der).unwrap()
		}

		assert_eq!(deserialize("\"0x0\""), 0);
		assert_eq!(deserialize("\"0x1\""), 1);
		assert_eq!(
			deserialize("\"0xffffffffffffffff\""),
			u64::max_value() as u128
		);
		assert_eq!(
			deserialize("\"0x10000000000000000\""),
			u64::max_value() as u128 + 1
		);
	}

	/// The `commitment.data_root is none`.
	fn header_v3() -> THeader {
		let commitment = v3::KateCommitment {
				commitment: hex!("80e949ebdaf5c13e09649c587c6b1905fb770b4a6843abaac6b413e3a7405d9825ac764db2341db9b7965965073e975980e949ebdaf5c13e09649c587c6b1905fb770b4a6843abaac6b413e3a7405d9825ac764db2341db9b7965965073e9759").to_vec(),
				..Default::default()
			};
		let extension = extension::v3::HeaderExtension {
			commitment,
			..Default::default()
		};

		THeader {
			extension: extension.into(),
			..Default::default()
		}
	}

	/// It creates a corrupted V3 header and the associated error on decodification.
	fn corrupted_header() -> (Vec<u8>, Error) {
		let mut encoded = header_v3().encode();
		encoded.remove(110);

		let error = THeader::decode(&mut encoded.as_slice()).unwrap_err();

		(encoded, error)
	}

	#[test_case( header_v3().encode().as_ref() => Ok(header_v3()) ; "Decode V3 header")]
	#[test_case( corrupted_header().0.as_ref() => Err(corrupted_header().1) ; "Decode corrupted header")]
	fn header_decoding(mut encoded_header: &[u8]) -> Result<THeader, Error> {
		Header::decode(&mut encoded_header)
	}

	fn header_serde_encode<N: BlockNumber, H: HashT>(header: Header<N, H>) -> String
	where
		H::Output: TypeInfo,
	{
		serde_json::to_string(&header).unwrap_or_default()
	}

	#[test_case(header_serde_encode(header_v3()) => Ok(header_v3()) ; "Serde V3 header")]
	fn header_serde(json_header: String) -> Result<THeader, String> {
		serde_json::from_str(&json_header).map_err(|serde_err| format!("{}", serde_err))
	}

	fn header() -> (THeader, H256) {
		let commitment = v3::KateCommitment {
			rows:1,
			cols:4,
			data_root: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
			commitment: hex!("ace5bc6a21eef8b28987eb878e0b97b5ae3c8b8e05efe957802dc0008b23327b349f62ec96bcee48bdc30f6bb670f3d1ace5bc6a21eef8b28987eb878e0b97b5ae3c8b8e05efe957802dc0008b23327b349f62ec96bcee48bdc30f6bb670f3d1").into()
		};
		let extension = extension::v3::HeaderExtension {
			commitment,
			app_lookup: DataLookup::from_id_and_len_iter([(AppId(0), 1)].into_iter())
				.expect("Valid DataLookup .qed"),
		};
		let digest = Digest {
			logs: vec![
				DigestItem::PreRuntime(
					hex!("42414245").into(),
					hex!("0201000000aa23040500000000").into()),
					DigestItem::Seal(
						hex!("42414245").into(),
						hex!("82a0c0a19f4548adcd575cdc37555b3aeaaae4048a6d39013b98f412420977752459afdc5295d026a4d3476d4d8d3d5e55c3c109235350d9242b4e3132db7e88").into(),
						),
			]
		};

		let header = THeader {
			parent_hash: hex!("84a90eef1c4a75c3cbfdf5095450725f924f1a2696946f6d9cf8401f6db99128")
				.into(),
			number: 368726,
			state_root: hex!("586140044543d7bb7471781322bcc2d7e4290716fbac7267e001843162f151d8")
				.into(),
			extrinsics_root: hex!(
				"9ea39eed403afde19c6688785530654a601bb62f0c178c78563933e303e001b6"
			)
			.into(),
			extension: extension.into(),
			digest,
		};
		let hash = header.hash();

		// Check `hash` is what we have in the testnet.
		assert_eq!(
			hash,
			H256(hex!(
				"c9941af1cb862db9f2e4c0c94f457d1217b363ecf6e6cc0dbeb5cbfeb35fbc12"
			))
		);

		(header, hash)
	}

	fn corrupted_kate_commitment(header_and_hash: (THeader, H256)) -> (THeader, H256) {
		let (mut header, hash) = header_and_hash;

		match header.extension {
			extension::HeaderExtension::V3(ref mut ext) => {
				ext.commitment.commitment = b"invalid commitment v3".to_vec();
			},
		};

		(header, hash)
	}

	fn corrupted_kate_data_root(header_and_hash: (THeader, H256)) -> (THeader, H256) {
		let (mut header, hash) = header_and_hash;

		match header.extension {
			extension::HeaderExtension::V3(ref mut ext) => {
				ext.commitment.data_root = H256::repeat_byte(2u8);
			},
		};

		(header, hash)
	}

	fn corrupted_kate_cols(header_and_hash: (THeader, H256)) -> (THeader, H256) {
		let (mut header, hash) = header_and_hash;

		match header.extension {
			extension::HeaderExtension::V3(ref mut ext) => {
				ext.commitment.cols += 2;
			},
		};

		(header, hash)
	}

	fn corrupted_kate_rows(header_and_hash: (THeader, H256)) -> (THeader, H256) {
		let (mut header, hash) = header_and_hash;

		match header.extension {
			extension::HeaderExtension::V3(ref mut ext) => {
				ext.commitment.rows += 2;
			},
		};

		(header, hash)
	}

	fn corrupted_number(mut header_and_hash: (THeader, H256)) -> (THeader, H256) {
		header_and_hash.0.number += 1;
		header_and_hash
	}

	fn corrupted_state_root(mut header_and_hash: (THeader, H256)) -> (THeader, H256) {
		header_and_hash.0.state_root.0[0] ^= 0xFFu8;
		header_and_hash
	}
	fn corrupted_parent(mut header_and_hash: (THeader, H256)) -> (THeader, H256) {
		header_and_hash.0.parent_hash.0[0] ^= 0xFFu8;
		header_and_hash
	}

	#[test_case( header() => true ; "Valid header hash")]
	#[test_case( corrupted_kate_commitment(header()) => false; "Corrupted commitment in kate")]
	#[test_case( corrupted_kate_data_root(header()) => false; "Corrupted data root in kate")]
	#[test_case( corrupted_kate_cols(header()) => false; "Corrupted cols in kate")]
	#[test_case( corrupted_kate_rows(header()) => false; "Corrupted rows in kate")]
	#[test_case( corrupted_number(header()) => false )]
	#[test_case( corrupted_state_root(header()) => false )]
	#[test_case( corrupted_parent(header()) => false )]
	fn header_corruption(header_and_hash: (THeader, H256)) -> bool {
		let (header, hash) = header_and_hash;
		header.hash() == hash
	}
}
