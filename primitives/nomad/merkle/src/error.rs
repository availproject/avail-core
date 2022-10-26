use sp_core::H256;
#[cfg(feature = "std")]
use thiserror::Error;

/// Tree Errors
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, Clone, Copy)]
pub enum VerifyingError {
	/// Failed proof verification
	#[cfg_attr(
		feature = "std",
		error("Proof verification failed. Root is {expected}, produced is {actual}")
	)]
	#[allow(dead_code)]
	VerificationFailed {
		/// The expected root (this tree's current root)
		expected: H256,
		/// The root produced by branch evaluation
		actual: H256,
	},
}

/// Error type for merkle tree ops.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum TreeError {
	/// Trying to push in a leaf
	#[cfg_attr(feature = "std", error("Trying to push in a leaf"))]
	LeafReached,
	/// No more space in the MerkleTree
	#[cfg_attr(feature = "std", error("No more space in the MerkleTree"))]
	MerkleTreeFull,
	/// MerkleTree is invalid
	#[cfg_attr(feature = "std", error("MerkleTree is invalid"))]
	Invalid,
	/// Incorrect Depth provided
	#[cfg_attr(feature = "std", error("Incorrect Depth provided"))]
	DepthTooSmall,
	/// Depth provided too large
	#[cfg_attr(feature = "std", error("Provided tree depth exceeded 32"))]
	DepthTooLarge,
}
