//! Data-Avail implementation of a block header.
use super::HeaderExtension;
use crate::sp_std::fmt::Debug;
use codec::{Decode, Encode};
use sp_core::H256;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use {scale_info::TypeInfo, sp_runtime::Digest, sp_runtime_interface::pass_by::PassByCodec};

#[cfg(not(feature = "runtime"))]
use avail_core_substrate::digest::Digest;

/// Abstraction over a block header for a substrate chain.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
	feature = "serde",
	serde(deny_unknown_fields, rename_all = "camelCase")
)]
#[cfg_attr(feature = "runtime", derive(TypeInfo))]
pub struct Header {
	/// The parent hash.
	pub parent_hash: H256,
	/// The block number.
	#[cfg_attr(feature = "serde", serde(with = "number_serde"))]
	#[codec(compact)]
	pub number: u32,
	/// The state trie merkle root
	pub state_root: H256,
	/// The merkle root of the extrinsics.
	pub extrinsics_root: H256,
	/// A chain-specific digest of data useful for light clients or referencing auxiliary data.
	pub digest: Digest,
	/// Data Availability header extension.
	pub extension: HeaderExtension,
}

impl Header {
	/// Creates a header V1
	#[inline]
	pub fn new(
		number: u32,
		extrinsics_root: H256,
		state_root: H256,
		parent_hash: H256,
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

	/* 	/// Convenience helper for computing the hash of the header without having
	/// to import the trait.
	#[inline]
	pub fn hash(&self) -> H256 {
		H256::hash_of(self)
	} */
}

/* impl Debug for Header {
	fn fmt(&self, f: &mut Formatter<'_>) -> crate::sp_std::fmt::Result {
		f.debug_struct("Header")
			.field("parent_hash", h256_to_hex(&self.parent_hash).into())
			.field("number", &self.number)
			.field("state_root", h256_to_hex(&self.state_root).into())
			.field("extrinsics_root", h256_to_hex(&self.extrinsics_root).into())
			.field("digest", &self.digest)
			.field("extension", &self.extension)
			.finish()
	}
} */

#[derive(Debug, Clone, Copy, Eq, PartialEq, Encode, Decode)]
#[cfg_attr(feature = "runtime", derive(TypeInfo, PassByCodec))]
pub enum HeaderVersion {
	V3 = 2, // Current one
}

/// This module adds serialization support to `Header::number` field.
#[cfg(feature = "serde")]
mod number_serde {
	use serde::{Deserializer, Serializer};

	use super::*;

	pub fn serialize<S>(n: &u32, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serde::Serialize::serialize(&n, serializer)
	}

	pub fn deserialize<'de, D>(d: D) -> Result<u32, D::Error>
	where
		D: Deserializer<'de>,
	{
		let buf = String::deserialize(d)?;
		let without_prefix = buf.trim_start_matches("0x");
		// TODO Marko
		Ok(u32::from_str_radix(without_prefix, 16).unwrap())
	}
}

/* #[cfg(all(test, feature = "runtime"))]
mod tests {
	use codec::Error;
	use hex_literal::hex;
	use sp_core::H256;
	use sp_runtime::{traits::BlakeTwo256, DigestItem};
	use test_case::test_case;

	use super::*;
	use crate::{kate_commitment::v3, AppId, DataLookup};

	type THeader = Header;

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

	fn header_serde_encode<N: BlockNumber, H: HashT>(header: Header) -> String
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
 */
