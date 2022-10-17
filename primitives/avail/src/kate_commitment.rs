use codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::H256;
use sp_std::vec::Vec;

/// Customized extrinsics root to save the commitment.
#[derive(PartialEq, Eq, Clone, sp_core::RuntimeDebug, Default, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "std", serde(deny_unknown_fields))]
pub struct KateCommitment {
	/// Rows
	#[codec(compact)]
	pub rows: u16,
	/// Cols
	#[codec(compact)]
	pub cols: u16,
	/// The merkle root of the data submitted
	pub data_root: H256,
	/// Plonk commitment.
	pub commitment: Vec<u8>,
}

/*
/// Marker trait for types `T` that can be use as `Hash` in `ExtrinsicsRoot`.
pub trait KateExtrinsicHash: Member + Codec {}

impl<T: Member + Codec> KateExtrinsicHash for T {}

impl<HashOutput: KateExtrinsicHash> ExtrinsicsWithCommitment for KateCommitment<HashOutput> {
	type HashOutput = HashOutput;

	fn hash(&self) -> &Self::HashOutput { &self.hash }

	fn commitment(&self) -> &Vec<u8> { &self.commitment }

	fn data_root(&self) -> &H256 { &self.data_root }

	fn new(hash: HashOutput) -> Self { hash.into() }

	fn new_with_commitment(
		hash: HashOutput,
		commitment: Vec<u8>,
		rows: u16,
		cols: u16,
		data_root: H256,
	) -> Self {
		Self {
			hash,
			commitment,
			rows,
			cols,
			data_root,
		}
	}
}

impl<Hash: KateExtrinsicHash> From<Hash> for KateCommitment<Hash> {
	fn from(hash: Hash) -> Self {
		Self {
			hash,
			commitment: Default::default(),
			rows: 0,
			cols: 0,
			data_root: Default::default(),
		}
	}
}*/

#[cfg(feature = "std")]
impl parity_util_mem::MallocSizeOf for KateCommitment {
	fn size_of(&self, ops: &mut parity_util_mem::MallocSizeOfOps) -> usize {
		self.commitment.size_of(ops)
			+ self.rows.size_of(ops)
			+ self.cols.size_of(ops)
			+ self.data_root.size_of(ops)
	}
}
