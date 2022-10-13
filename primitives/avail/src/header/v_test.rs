use codec::{Codec, Decode, Encode};
#[cfg(feature = "std")]
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::{RuntimeDebug, H256, U256};
use sp_runtime::{
	traits::{
		AtLeast32BitUnsigned, Hash as HashT, Header as HeaderT, MaybeDisplay, MaybeMallocSizeOf,
		MaybeSerialize, MaybeSerializeDeserialize, Member, SimpleBitOps,
	},
	Digest,
};
use sp_std::{convert::TryFrom, fmt::Debug};

use crate::{
	asdr::DataLookup,
	traits::{ExtendedHeader, ExtrinsicsWithCommitment as _},
	HeaderNumberTrait, KateCommitment, KateHashOutputTrait, KateHashTrait,
};

/// Abstraction over a block header for a substrate chain.
#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(deny_unknown_fields, rename_all = "camelCase"))]
pub struct Header<Number: HeaderNumberTrait, Hash: KateHashTrait> {
	/// The parent hash.:w
	pub parent_hash: Hash::Output,
	/// The block number.
	#[cfg_attr(feature = "std", serde(with = "number_serde"))]
	#[codec(compact)]
	pub number: Number,
	/// The state trie merkle root
	pub state_root: Hash::Output,

	/// New field:
	pub new_field: Vec<u8>,

	/// Hash and Kate Commitment
	pub extrinsics_root: KateCommitment<Hash::Output>,
	/// A chain-specific digest of data useful for light clients or referencing auxiliary data.
	pub digest: Digest,
	/// Application specific data index.
	pub app_data_lookup: DataLookup,
}

impl<N, H> Default for Header<N, H>
where
	N: HeaderNumberTrait + Default,
	H: KateHashTrait + Default,
{
	fn default() -> Self {
		Self {
			number: Default::default(),
			extrinsics_root: Default::default(),
			state_root: Default::default(),
			parent_hash: Default::default(),
			digest: Default::default(),
			app_data_lookup: Default::default(),
			new_field: Default::default(),
		}
	}
}

/// This module adds serialization support to `Header::number` field.
#[cfg(feature = "std")]
mod number_serde {
	use serde::{Deserializer, Serializer};

	use super::*;

	pub fn serialize<N, S>(n: &N, serializer: S) -> Result<S::Ok, S::Error>
	where
		N: HeaderNumberTrait,
		S: Serializer,
	{
		let u256: U256 = (*n).into();
		serde::Serialize::serialize(&u256, serializer)
	}

	pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
	where
		T: HeaderNumberTrait,
		D: Deserializer<'de>,
	{
		let u256: U256 = serde::Deserialize::deserialize(d)?;
		TryFrom::try_from(u256).map_err(|_| serde::de::Error::custom("Try from failed"))
	}
}

#[cfg(feature = "std")]
impl<Number, Hash> MallocSizeOf for Header<Number, Hash>
where
	Number: HeaderNumberTrait,
	Hash: KateHashTrait,
	Hash::Output: KateHashOutputTrait,
{
	fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
		self.parent_hash.size_of(ops)
			+ self.number.size_of(ops)
			+ self.state_root.size_of(ops)
			+ self.extrinsics_root.size_of(ops)
			+ self.digest.size_of(ops)
			+ self.app_data_lookup.size_of(ops)
			+ self.new_field.size_of(ops)
	}
}

impl<Number, Hash> HeaderT for Header<Number, Hash>
where
	Number: Member
		+ MaybeSerializeDeserialize
		+ Debug
		+ sp_std::hash::Hash
		+ MaybeDisplay
		+ AtLeast32BitUnsigned
		+ Codec
		+ Copy
		+ Into<U256>
		+ TryFrom<U256>
		+ sp_std::str::FromStr
		+ MaybeMallocSizeOf,
	Hash: HashT,
	Hash::Output: Default
		+ sp_std::hash::Hash
		+ Copy
		+ Member
		+ Ord
		+ MaybeSerialize
		+ Debug
		+ MaybeDisplay
		+ SimpleBitOps
		+ Codec
		+ MaybeMallocSizeOf,
{
	type Hash = <Hash as HashT>::Output;
	type Hashing = Hash;
	type Number = Number;

	fn number(&self) -> &Self::Number {
		&self.number
	}

	fn set_number(&mut self, num: Self::Number) {
		self.number = num
	}

	fn extrinsics_root(&self) -> &Self::Hash {
		self.extrinsics_root.hash()
	}

	fn set_extrinsics_root(&mut self, _root: Self::Hash) {
		todo!()
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
		log::debug!(
			target: super::LOG_TARGET,
			"Retrieving mutable reference to digest"
		);
		&mut self.digest
	}

	fn new(
		number: Self::Number,
		extrinsics_root_hash: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
	) -> Self {
		let extrinsics_root = extrinsics_root_hash.into();
		Self {
			number,
			parent_hash,
			state_root,
			digest,
			extrinsics_root,
			app_data_lookup: Default::default(),
			new_field: Default::default(),
		}
	}
}

impl<N, H> ExtendedHeader for Header<N, H>
where
	N: HeaderNumberTrait,
	H: KateHashTrait,
{
	type Hash = <H as HashT>::Output;
	type Number = N;
	type Root = KateCommitment<Self::Hash>;

	fn extrinsics_root(&self) -> &Self::Root {
		&self.extrinsics_root
	}

	fn set_extrinsics_root(&mut self, root: Self::Root) {
		self.extrinsics_root = root;
	}

	fn data_root(&self) -> H256 {
		self.extrinsics_root.data_root.into()
	}

	fn set_data_root(&mut self, data_root: H256) {
		self.extrinsics_root.data_root = data_root.into();
	}

	fn data_lookup(&self) -> &DataLookup {
		&self.app_data_lookup
	}

	/// Creates new header.
	fn new(
		number: Self::Number,
		extrinsics_root: Self::Root,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
		app_data_lookup: DataLookup,
	) -> Self {
		Self {
			number,
			extrinsics_root,
			state_root,
			parent_hash,
			digest,
			app_data_lookup,
			new_field: Default::default(),
		}
	}
}

impl<Number, Hash> Header<Number, Hash>
where
	Number: HeaderNumberTrait,
	Hash: KateHashTrait,
{
	/// Convenience helper for computing the hash of the header without having
	/// to import the trait.
	pub fn hash(&self) -> Hash::Output {
		Hash::hash_of(self)
	}
}

#[cfg(all(test, feature = "std"))]
mod tests {
	use hex_literal::hex;

	use super::*;

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
	#[test]
	fn ensure_format_is_unchanged() {
		use sp_runtime::{
			generic::{Digest, DigestItem},
			traits::BlakeTwo256,
		};

		use crate::KateCommitment;
		let extrinsic_root = KateCommitment {
			hash: BlakeTwo256::hash(b"4"),
			rows: 1,
			cols: 4,
			commitment: hex!("80e949ebdaf5c13e09649c587c6b1905fb770b4a6843abaac6b413e3a7405d9825ac764db2341db9b7965965073e975980e949ebdaf5c13e09649c587c6b1905fb770b4a6843abaac6b413e3a7405d9825ac764db2341db9b7965965073e9759").to_vec(),
			data_root: hex!("3fbf3227926cfa3f4167771e5ad91cfa2c2d7090667ce01e911ca90b4f315b11").into(),
		};
		let data_lookup = DataLookup {
			size: 1,
			index: vec![],
		};
		let header = Header::<u32, BlakeTwo256> {
			parent_hash: BlakeTwo256::hash(b"1"),
			number: 2,
			state_root: BlakeTwo256::hash(b"3"),
			extrinsics_root: extrinsic_root,
			digest: Digest {
				logs: vec![DigestItem::Other(b"5".to_vec())],
			},
			app_data_lookup: data_lookup,
			new_field: vec![42, 42, 42],
		};
		let encoded = header.encode();
		assert_eq!(encoded, hex!("92cdf578c47085a5992256f0dcf97d0b19f1f1c9de4d5fe30c3ace6191b6e5db08581348337b0f3e148620173daaa5f94d00d881705dcbf0aa83efdaba61d2ede10c2a2a2aeb8649214997574e20c464388a172420d25403682bbbb80c496831c8cc1f8f0d810180e949ebdaf5c13e09649c587c6b1905fb770b4a6843abaac6b413e3a7405d9825ac764db2341db9b7965965073e975980e949ebdaf5c13e09649c587c6b1905fb770b4a6843abaac6b413e3a7405d9825ac764db2341db9b7965965073e975904103fbf3227926cfa3f4167771e5ad91cfa2c2d7090667ce01e911ca90b4f315b11040004350100000000").to_vec());
	}
}
