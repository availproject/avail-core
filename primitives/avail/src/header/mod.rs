use codec::{Codec, Decode, Encode};
#[cfg(feature = "std")]
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Serializer};
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

const LOG_TARGET: &str = "header";

/// Abstraction over a versioned block header for a substrate chain.
#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo, Encode, Decode)]
pub enum Header<N: HeaderNumberTrait, H: KateHashTrait> {
	V1(v1::Header<N, H>),
}

/// It forwards the call to the inner version of the header. Any invalid version will return the
/// default value or execute an empty block.
macro_rules! forward_to_version {
	($self:ident, $function:ident) => {{
		match $self {
			Header::V1(header) => header.$function(),
		}
	}};

	($self:ident, $function:ident, $arg:expr) => {{
		match $self {
			Header::V1(header) => header.$function($arg),
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

	/// Convenience helper for computing the hash of the header without having
	/// to import the trait.
	pub fn hash(&self) -> H::Output { forward_to_version!(self, hash) }
}

#[cfg(feature = "std")]
impl<N, H> Serialize for Header<N, H>
where
	N: HeaderNumberTrait + Serialize,
	H: KateHashTrait,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match &self {
			Self::V1(ref header) => serializer.serialize_newtype_variant("Header", 0, "V1", header),
		}
	}
}

impl<N, H> Default for Header<N, H>
where
	N: HeaderNumberTrait + Default,
	H: KateHashTrait + Default,
{
	fn default() -> Self { Self::V1(Default::default()) }
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
		}
	}

	fn set_extrinsics_root(&mut self, root: Self::Hash) {
		match self {
			Self::V1(header) => HeaderT::set_extrinsics_root(header, root),
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
		Self::new_v1(
			number,
			extrinsics_root,
			state_root,
			parent_hash,
			digest,
			Default::default(),
		)
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
		number: Self::Number,
		extrinsics_root: Self::Root,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
		app_data_lookup: DataLookup,
	) -> Self {
		Self::new_v1(
			number,
			extrinsics_root,
			state_root,
			parent_hash,
			digest,
			app_data_lookup,
		)
	}
}
