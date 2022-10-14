use codec::{Codec, Decode, Encode};
#[cfg(feature = "std")]
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};
use scale_info::TypeInfo;
use sp_core::{RuntimeDebug, H256, U256};
use sp_runtime::{
	traits::{
		AtLeast32BitUnsigned, Hash as HashT, Header as HeaderT, MaybeDisplay, MaybeFromStr,
		MaybeMallocSizeOf, MaybeSerialize, MaybeSerializeDeserialize, Member, SimpleBitOps,
	},
	Digest,
};
use sp_runtime_interface::pass_by::{Codec as PassByCodecImpl, PassBy};
use sp_std::{convert::TryFrom, fmt::Debug, hash::Hash as StdHash};

use crate::{
	asdr::DataLookup,
	traits::{ExtendedHeader, ExtrinsicsWithCommitment as _},
	KateCommitment,
};

pub trait HeaderNumberTrait:
	Member
	+ AtLeast32BitUnsigned
	+ Codec
	+ MaybeSerializeDeserialize
	+ MaybeDisplay
	+ MaybeFromStr
	+ MaybeFromStr
	+ MaybeMallocSizeOf
	+ StdHash
	+ Copy
	+ Into<U256>
	+ TryFrom<U256>
	+ Debug
	+ Eq
{
}

impl<
		T: Member
			+ AtLeast32BitUnsigned
			+ Codec
			+ MaybeSerializeDeserialize
			+ MaybeDisplay
			+ MaybeFromStr
			+ MaybeMallocSizeOf
			+ StdHash
			+ Copy
			+ Into<U256>
			+ TryFrom<U256>
			+ Debug
			+ Eq,
	> HeaderNumberTrait for T
{
}

pub trait KateHashTrait: HashT {}
impl<T: HashT> KateHashTrait for T {}

pub trait KateHashOutputTrait:
	MaybeDisplay + Decode + MaybeMallocSizeOf + SimpleBitOps + Ord
{
}

impl<T: MaybeDisplay + Decode + MaybeMallocSizeOf + SimpleBitOps + Ord> KateHashOutputTrait for T {}

pub mod v1;
#[cfg(feature = "header-backward-compatibility-test")]
pub mod v_test;

#[cfg(feature = "std")]
pub mod serde;

const LOG_TARGET: &str = "header";

/// Abstraction over a versioned block header for a substrate chain.
#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo, Encode, Decode)]
pub enum Header<N: HeaderNumberTrait, H: KateHashTrait> {
	V1(v1::Header<N, H>),
	// Add new versions here...

	// End new versions.
	#[cfg(feature = "header-backward-compatibility-test")]
	VTest(v_test::Header<N, H>),
}

/// It forwards the call to the inner version of the header. Any invalid version will return the
/// default value or execute an empty block.
macro_rules! forward_to_version {
	($self:ident, $function:ident) => {{
		match $self {
			Header::V1(header) => header.$function(),
			#[cfg(feature = "header-backward-compatibility-test")]
			Header::VTest(header) => header.$function(),
		}
	}};

	($self:ident, $function:ident, $arg:expr) => {{
		match $self {
			Header::V1(header) => header.$function($arg),
			#[cfg(feature = "header-backward-compatibility-test")]
			Header::VTest(header) => header.$function($arg),
		}
	}};
}

impl<N, H> Header<N, H>
where
	N: HeaderNumberTrait,
	H: KateHashTrait,
{
	#[inline]
	/// Creates a header V1
	pub fn new_v1(
		number: N,
		extrinsics_root: <Self as ExtendedHeader>::Root,
		state_root: H::Output,
		parent_hash: H::Output,
		digest: Digest,
		app_data_lookup: DataLookup,
	) -> Self {
		let inner = <v1::Header<N, H> as ExtendedHeader>::new(
			number,
			extrinsics_root,
			state_root,
			parent_hash,
			digest,
			app_data_lookup,
		);

		Self::V1(inner)
	}

	#[cfg(feature = "header-backward-compatibility-test")]
	pub fn new_v_test(
		number: N,
		extrinsics_root: <Self as ExtendedHeader>::Root,
		state_root: H::Output,
		parent_hash: H::Output,
		digest: Digest,
		app_data_lookup: DataLookup,
	) -> Self {
		let inner = <v_test::Header<N, H> as ExtendedHeader>::new(
			number,
			extrinsics_root,
			state_root,
			parent_hash,
			digest,
			app_data_lookup,
		);

		Self::VTest(inner)
	}

	/// Convenience helper for computing the hash of the header without having
	/// to import the trait.
	pub fn hash(&self) -> H::Output { forward_to_version!(self, hash) }
}

impl<N, H> Default for Header<N, H>
where
	N: HeaderNumberTrait + Default,
	H: KateHashTrait + Default,
{
	#[cfg(not(feature = "header-backward-compatibility-test"))]
	fn default() -> Self { Self::V1(Default::default()) }

	#[cfg(feature = "header-backward-compatibility-test")]
	fn default() -> Self { Self::VTest(Default::default()) }
}

impl<Number, Hash> PassBy for Header<Number, Hash>
where
	Number: HeaderNumberTrait,
	Hash: KateHashTrait,
{
	type PassBy = PassByCodecImpl<Header<Number, Hash>>;
}

#[cfg(feature = "std")]
impl<Number, Hash> MallocSizeOf for Header<Number, Hash>
where
	Number: HeaderNumberTrait,
	Hash: KateHashTrait,
	Hash::Output: KateHashOutputTrait,
{
	fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
		forward_to_version!(self, size_of, ops)
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

	fn number(&self) -> &Self::Number { forward_to_version!(self, number) }

	fn set_number(&mut self, num: Self::Number) {
		forward_to_version!(self, set_number, num);
	}

	fn extrinsics_root(&self) -> &Self::Hash {
		match &self {
			Self::V1(ref header) => HeaderT::extrinsics_root(header),
			#[cfg(feature = "header-backward-compatibility-test")]
			Self::VTest(ref header) => HeaderT::extrinsics_root(header),
		}
	}

	fn set_extrinsics_root(&mut self, root: Self::Hash) {
		match self {
			Self::V1(header) => HeaderT::set_extrinsics_root(header, root),
			#[cfg(feature = "header-backward-compatibility-test")]
			Self::VTest(header) => HeaderT::set_extrinsics_root(header, root),
		}
	}

	fn state_root(&self) -> &Self::Hash { forward_to_version!(self, state_root) }

	fn set_state_root(&mut self, root: Self::Hash) {
		forward_to_version!(self, set_state_root, root);
	}

	fn parent_hash(&self) -> &Self::Hash { forward_to_version!(self, parent_hash) }

	fn set_parent_hash(&mut self, hash: Self::Hash) {
		forward_to_version!(self, set_parent_hash, hash);
	}

	fn digest(&self) -> &Digest { forward_to_version!(self, digest) }

	fn digest_mut(&mut self) -> &mut Digest { forward_to_version!(self, digest_mut) }

	fn new(
		number: Self::Number,
		extrinsics_root_hash: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
	) -> Self {
		let extrinsics_root = <<Self as ExtendedHeader>::Root>::new(extrinsics_root_hash);
		let lookup = Default::default();

		#[cfg(not(feature = "header-backward-compatibility-test"))]
		let header = Self::new_v1(
			number,
			extrinsics_root,
			state_root,
			parent_hash,
			digest,
			lookup,
		);

		#[cfg(feature = "header-backward-compatibility-test")]
		let header = Self::new_v_test(
			number,
			extrinsics_root,
			state_root,
			parent_hash,
			digest,
			lookup,
		);

		header
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

	fn extrinsics_root(&self) -> &Self::Root { forward_to_version!(self, extrinsics_root) }

	fn set_extrinsics_root(&mut self, root: Self::Root) {
		forward_to_version!(self, set_extrinsics_root, root);
	}

	fn data_root(&self) -> H256 { forward_to_version!(self, data_root) }

	fn set_data_root(&mut self, data_root: H256) {
		forward_to_version!(self, set_data_root, data_root);
	}

	fn data_lookup(&self) -> &DataLookup { forward_to_version!(self, data_lookup) }

	/// Creates new header.
	fn new(
		n: Self::Number,
		extrinsics: Self::Root,
		state: Self::Hash,
		parent: Self::Hash,
		digest: Digest,
		lookup: DataLookup,
	) -> Self {
		#[cfg(not(feature = "header-backward-compatibility-test"))]
		let header = Self::new_v1(n, extrinsics, state, parent, digest, lookup);

		#[cfg(feature = "header-backward-compatibility-test")]
		let header = Self::new_v_test(n, extrinsics, state, parent, digest, lookup);

		header
	}
}

#[cfg(test)]
mod tests {
	use codec::Error;
	use hex_literal::hex;
	use sp_runtime::{traits::BlakeTwo256, DigestItem};
	use test_case::test_case;

	use super::*;

	fn extrinsic_root() -> KateCommitment<H256> {
		KateCommitment {
			hash: BlakeTwo256::hash(b"4"),
			rows: 1,
			cols: 4,
			commitment: hex!("80e949ebdaf5c13e09649c587c6b1905fb770b4a6843abaac6b413e3a7405d9825ac764db2341db9b7965965073e975980e949ebdaf5c13e09649c587c6b1905fb770b4a6843abaac6b413e3a7405d9825ac764db2341db9b7965965073e9759").to_vec(),
			data_root: hex!("3fbf3227926cfa3f4167771e5ad91cfa2c2d7090667ce01e911ca90b4f315b11").into(),
		}
	}

	fn header_v1() -> Header<u32, BlakeTwo256> {
		let header = v1::Header::<u32, BlakeTwo256> {
			parent_hash: BlakeTwo256::hash(b"1"),
			number: 2,
			state_root: BlakeTwo256::hash(b"3"),
			extrinsics_root: extrinsic_root(),
			digest: Digest {
				logs: vec![DigestItem::Other(b"5".to_vec())],
			},
			app_data_lookup: DataLookup {
				size: 1,
				index: vec![],
			},
		};

		Header::V1(header)
	}

	#[cfg(not(feature = "header-backward-compatibility-test"))]
	fn header_test() -> Header<u32, BlakeTwo256> { header_v1() }

	#[cfg(feature = "header-backward-compatibility-test")]
	fn header_test() -> Header<u32, BlakeTwo256> {
		let header = v_test::Header::<u32, BlakeTwo256> {
			parent_hash: BlakeTwo256::hash(b"1"),
			number: 2,
			state_root: BlakeTwo256::hash(b"3"),
			extrinsics_root: extrinsic_root(),
			digest: Digest {
				logs: vec![DigestItem::Other(b"5".to_vec())],
			},
			app_data_lookup: DataLookup {
				size: 1,
				index: vec![],
			},
			new_field: vec![42, 42],
		};

		Header::VTest(header)
	}

	#[test_case( header_v1().encode().as_ref() => Ok(header_v1()) ; "Decode V1 header")]
	#[test_case( header_test().encode().as_ref() => Ok(header_test()) ; "Decode test header")]
	fn header_decoding(mut encoded_header: &[u8]) -> Result<Header<u32, BlakeTwo256>, Error> {
		Header::decode(&mut encoded_header)
	}

	fn header_serde_encode<N: HeaderNumberTrait, H: KateHashTrait>(header: Header<N, H>) -> String {
		serde_json::to_string(&header).unwrap_or_default()
	}

	#[test_case( header_serde_encode(header_v1()) => Ok(header_v1()) ; "Serde V1 header")]
	#[test_case( header_serde_encode(header_test()) => Ok(header_test()) ; "Serde test header")]
	fn header_serde(json_header: String) -> Result<Header<u32, BlakeTwo256>, String> {
		serde_json::from_str(&json_header).map_err(|serde_err| format!("{}", serde_err))
	}
}
