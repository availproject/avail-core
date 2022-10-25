use beefy_merkle_tree::MerkleProof;
use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::H256;
use sp_runtime::traits::SaturatedConversion;
use sp_std::vec::Vec;

/// Wrapper of `beefy-merkle-tree::MerkleProof` with codec support.
#[derive(Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct DataProof {
	/// Root hash of generated merkle tree.
	pub root: H256,
	/// Proof items (does not contain the leaf hash, nor the root obviously).
	///
	/// This vec contains all inner node hashes necessary to reconstruct the root hash given the
	/// leaf hash.
	pub proof: Vec<H256>,
	/// Number of leaves in the original tree.
	///
	/// This is needed to detect a case where we have an odd number of leaves that "get promoted"
	/// to upper layers.
	#[codec(compact)]
	pub number_of_leaves: u32,
	/// Index of the leaf the proof is for (0-based).
	#[codec(compact)]
	pub leaf_index: u32,
	/// Leaf content.
	pub leaf: H256,
}

impl<T> From<MerkleProof<T>> for DataProof
where
	H256: From<T>,
{
	fn from(merkle_proof: MerkleProof<T>) -> Self {
		let proof = merkle_proof
			.proof
			.into_iter()
			.map(Into::into)
			.collect::<Vec<_>>();
		Self {
			proof,
			root: merkle_proof.root.into(),
			number_of_leaves: merkle_proof.number_of_leaves.saturated_into(),
			leaf_index: merkle_proof.leaf_index.saturated_into(),
			leaf: merkle_proof.leaf.into(),
		}
	}
}

impl DataProof {
	pub fn to_beefy_merkle_proof<T: From<H256>>(self) -> MerkleProof<T> {
		let proof = self.proof.into_iter().map(Into::into).collect::<Vec<_>>();
		MerkleProof {
			root: self.root.into(),
			proof,
			number_of_leaves: self.number_of_leaves as usize,
			leaf_index: self.leaf_index as usize,
			leaf: self.leaf.into(),
		}
	}
}
