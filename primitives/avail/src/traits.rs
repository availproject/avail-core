use codec::{Codec, Decode};
use sp_core::U256;
use sp_runtime::{
	traits::{
		AtLeast32BitUnsigned, Hash as HashT, MaybeDisplay, MaybeFromStr, MaybeMallocSizeOf,
		MaybeSerializeDeserialize, Member, SimpleBitOps,
	},
	Digest,
};
use sp_std::{convert::TryFrom, fmt::Debug, hash::Hash as StdHash};

use crate::header::HeaderExtension;

/// Header block number trait.
pub trait HeaderBlockNumber:
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
	> HeaderBlockNumber for T
{
}

/// Header hash.
pub trait HeaderHash: HashT {}
impl<T: HashT> HeaderHash for T {}

pub trait HeaderHashOutput: MaybeDisplay + Decode + MaybeMallocSizeOf + SimpleBitOps + Ord {}
impl<T: MaybeDisplay + Decode + MaybeMallocSizeOf + SimpleBitOps + Ord> HeaderHashOutput for T {}

/*
pub trait ExtrinsicsWithCommitment {
	type HashOutput;

	fn hash(&self) -> &Self::HashOutput;
	fn commitment(&self) -> &Vec<u8>;
	fn data_root(&self) -> &H256;

	fn new(hash: Self::HashOutput) -> Self;

	fn new_with_commitment(
		hash: Self::HashOutput,
		commitment: Vec<u8>,
		rows: u16,
		cols: u16,
		data_root: H256,
	) -> Self;
}*/

/// Extended header with :
///     - Extrinsics with commitments.
///     - Application data lookup.
pub trait ExtendedHeader {
	/// Header number.
	type Number;

	/// Header hash type
	type Hash;

	/*
	/// Root Data.
	type Root: ExtrinsicsWithCommitment<HashOutput = Self::Hash>;

	fn extrinsics_root(&self) -> &Self::Root;
	fn set_extrinsics_root(&mut self, root: Self::Root);

	fn data_root(&self) -> H256;
	fn set_data_root(&mut self, root: H256);

	fn data_lookup(&self) -> &DataLookup;
	*/

	/// Creates new header.
	fn new(
		number: Self::Number,
		extrinsics_root: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
		extension: HeaderExtension,
	) -> Self;

	fn extension(&self) -> &HeaderExtension;

	fn set_extension(&mut self, extension: HeaderExtension);
}
