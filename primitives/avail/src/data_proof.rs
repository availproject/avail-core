use beefy_merkle_tree::{Hash, Hasher, MerkleProof};
use codec::{Decode, Encode};
use frame_support::ensure;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::H256;
use sp_io::hashing::sha2_256;
use sp_std::{convert::TryFrom, vec::Vec};
#[cfg(feature = "std")]
use thiserror::Error;

/// Sha2 256 wrapper which supports `beefy-merkle-tree::Hasher`.
#[derive(Copy, Clone)]
pub struct HasherSha256 {}

impl Hasher for HasherSha256 {
	fn hash(data: &[u8]) -> Hash { sha2_256(data) }
}

/// Wrapper of `beefy-merkle-tree::MerkleProof` with codec support.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Default)]
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

/// Conversion error from `beefy-merkle-tree::MerkleProof`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum DataProofTryFromError {
	/// Root cannot be converted into `H256`.
	#[cfg_attr(feature = "std", error("Root cannot be converted into `H256`"))]
	InvalidRoot,
	/// Leaf cannot be converted into `H256`.
	#[cfg_attr(feature = "std", error("Leaf cannot be converted into `H256`"))]
	InvalidLeaf,
	/// The given index of proofs cannot be converted into `H256`.
	#[cfg_attr(feature = "std", error("Proof at {0} cannot be converted into `H256`"))]
	InvalidProof(usize),
	/// Number of leaves overflowed
	#[cfg_attr(feature = "std", error("Number of leaves overflowed"))]
	OverflowedNumberOfLeaves,
	/// Number of leaves must be greater than zero.
	#[cfg_attr(feature = "std", error("Number of leaves cannot be zero"))]
	InvalidNumberOfLeaves,
	/// Leaf index overflowed
	#[cfg_attr(feature = "std", error("Leaf index overflowed"))]
	OverflowedLeafIndex,
	/// Leaf index overflowed or invalid (greater or equal to `number_of_leaves`)
	#[cfg_attr(feature = "std", error("Leaf index is invalid"))]
	InvalidLeafIndex,
}

impl<T> TryFrom<&MerkleProof<T>> for DataProof
where
	T: AsRef<[u8]>,
{
	type Error = DataProofTryFromError;

	fn try_from(merkle_proof: &MerkleProof<T>) -> Result<Self, Self::Error> {
		use DataProofTryFromError::*;

		let root = <[u8; 32]>::try_from(merkle_proof.root.as_ref())
			.map_err(|_| InvalidRoot)?
			.into();
		let leaf = <[u8; 32]>::try_from(merkle_proof.leaf.as_ref())
			.map_err(|_| InvalidLeaf)?
			.into();
		let proof = merkle_proof
			.proof
			.iter()
			.enumerate()
			.map(|(idx, proof)| {
				<[u8; 32]>::try_from(proof.as_ref())
					.map_err(|_| InvalidProof(idx))
					.map(|raw| H256(raw))
			})
			.collect::<Result<Vec<H256>, _>>()?;
		let number_of_leaves =
			u32::try_from(merkle_proof.number_of_leaves).map_err(|_| OverflowedNumberOfLeaves)?;
		ensure!(number_of_leaves != 0, InvalidNumberOfLeaves);

		let leaf_index = u32::try_from(merkle_proof.leaf_index).map_err(|_| OverflowedLeafIndex)?;
		ensure!(leaf_index < number_of_leaves, InvalidLeafIndex);

		Ok(Self {
			proof,
			root,
			leaf,
			number_of_leaves,
			leaf_index,
		})
	}
}

impl DataProof {
	pub fn to_beefy_merkle_proof<T: From<[u8; 32]>>(self) -> MerkleProof<T> {
		let proof = self
			.proof
			.into_iter()
			.map(|proof| proof.to_fixed_bytes())
			.collect::<Vec<_>>();
		MerkleProof {
			root: self.root.to_fixed_bytes(),
			proof,
			number_of_leaves: self.number_of_leaves as usize,
			leaf_index: self.leaf_index as usize,
			leaf: self.leaf.to_fixed_bytes().into(),
		}
	}
}

#[cfg(test)]
mod test {
	use hex_literal::hex;
	use sp_std::cmp::min;
	use test_case::test_case;

	use super::*;

	fn leaves() -> Vec<Vec<u8>> {
		(0u8..7)
			.map(|idx| H256::repeat_byte(idx).to_fixed_bytes().to_vec())
			.collect::<Vec<_>>()
	}

	/// Creates a merkle proof of `leaf_index`.
	///
	/// If `leaf_index >= number_of_leaves`, it will create a fake proof using the latest possible
	/// index and overwriting the proof. That case is used to test transformations into
	/// `DataProof`.
	fn merkle_proof_idx(leaf_index: usize) -> MerkleProof<Vec<u8>> {
		let leaves = leaves();
		let index = min(leaf_index, leaves.len() - 1);

		let mut proof = beefy_merkle_tree::merkle_proof::<HasherSha256, _, _>(leaves, index);
		proof.leaf_index = leaf_index;
		proof
	}

	fn invalid_merkle_proof_zero_leaves() -> MerkleProof<Vec<u8>> {
		MerkleProof {
			root: H256::default().to_fixed_bytes(),
			proof: vec![],
			number_of_leaves: 0,
			leaf_index: 0,
			leaf: H256::default().to_fixed_bytes().to_vec(),
		}
	}

	fn expected_data_proof_1() -> Result<DataProof, DataProofTryFromError> {
		Ok(DataProof {
			root: hex!("125c1991d3f1bd871bc65fcdb2f71e867f92303295fcaf83fa182d011c2a9ee0").into(),
			proof: vec![
				hex!("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925").into(),
				hex!("10939918674b58bbf7a19e380c334642ef87c5109559c9e9ca0ca24278944d5e").into(),
				hex!("e6a4d8842ef4253ccaafe54a528696976ab98b91c926278d1f8dbf56fa601c11").into(),
			],
			number_of_leaves: 7,
			leaf_index: 1,
			leaf: H256::repeat_byte(1).to_fixed_bytes().into(),
		})
	}

	fn expected_data_proof_0() -> Result<DataProof, DataProofTryFromError> {
		Ok(DataProof {
			root: hex!("125c1991d3f1bd871bc65fcdb2f71e867f92303295fcaf83fa182d011c2a9ee0").into(),
			proof: vec![
				hex!("72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793").into(),
				hex!("10939918674b58bbf7a19e380c334642ef87c5109559c9e9ca0ca24278944d5e").into(),
				hex!("e6a4d8842ef4253ccaafe54a528696976ab98b91c926278d1f8dbf56fa601c11").into(),
			],
			number_of_leaves: 7,
			leaf_index: 0,
			leaf: H256::repeat_byte(0).to_fixed_bytes().into(),
		})
	}

	fn expected_data_proof_6() -> Result<DataProof, DataProofTryFromError> {
		Ok(DataProof {
			root: hex!("125c1991d3f1bd871bc65fcdb2f71e867f92303295fcaf83fa182d011c2a9ee0").into(),
			proof: vec![
				hex!("f19838ccc7d697a5dfadf94e0b63577b98c1d8e96d0c242a12eca6d95fd8f288").into(),
				hex!("4fc5f858a182a0445d5ec5bf71477fd9e076bf383f1ba8090e1809eeaacce894").into(),
			],
			number_of_leaves: 7,
			leaf_index: 6,
			leaf: H256::repeat_byte(6).to_fixed_bytes().into(),
		})
	}

	#[test_case( merkle_proof_idx(0) => expected_data_proof_0(); "From merkle proof 0")]
	#[test_case( merkle_proof_idx(1) => expected_data_proof_1(); "From merkle proof 1")]
	#[test_case( merkle_proof_idx(6) => expected_data_proof_6(); "From merkle proof 6")]
	#[test_case( merkle_proof_idx(7) => Err(DataProofTryFromError::InvalidLeafIndex); "From invalid leaf index")]
	#[test_case( invalid_merkle_proof_zero_leaves() => Err(DataProofTryFromError::InvalidNumberOfLeaves); "From invalid number of leaves")]
	fn from_beefy(beefy_proof: MerkleProof<Vec<u8>>) -> Result<DataProof, DataProofTryFromError> {
		let data_proof = DataProof::try_from(&beefy_proof)?;

		// Check backward transformation.
		let new_beefy_proof = data_proof.clone().to_beefy_merkle_proof::<Vec<u8>>();
		assert_eq!(beefy_proof, new_beefy_proof);

		Ok(data_proof)
	}
}
