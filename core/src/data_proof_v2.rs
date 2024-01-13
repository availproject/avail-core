use std::fmt::format;
#[cfg(feature = "runtime")]
use binary_merkle_tree::MerkleProof;
use codec::{Decode, Encode};
use ethabi::{encode, Token};
use frame_support::BoundedVec;
#[cfg(feature = "runtime")]
use nomad_core::keccak256_concat;
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use serde::{de, Deserializer, Serializer};
use sp_core::{ConstU32, H256};
use sp_std::vec;
use sp_std::vec::Vec;
use thiserror_no_std::Error;
use scale_info::prelude::string::String;

/// Max data supported on bidge (Ethereum calldata limits)
pub const BOUNDED_DATA_MAX_LENGTH: u32 = 102_400;

/// Maximum size of data allowed in the bridge
pub type BoundedData = BoundedVec<u8, ConstU32<BOUNDED_DATA_MAX_LENGTH>>;

/// Possible types of Messages allowed by Avail to bridge to other chains.
#[derive(
TypeInfo, Debug, Default, Eq, Clone, Encode, Decode, PartialEq,
)]
pub enum MessageType {
    ArbitraryMessage,
    #[default]
    FungibleToken,
}

impl Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(match *self {
            MessageType::ArbitraryMessage => "0x01",
            MessageType::FungibleToken => "0x02",
        })
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        if s == "0x01" {
            Ok(MessageType::ArbitraryMessage)
        } else if s == "0x02" {
            Ok(MessageType::FungibleToken)
        } else {
            Err(<D::Error as de::Error>::custom("Unsupported value {}"))
        }
    }
}


impl From<MessageType> for Vec<u8> {
    fn from(msg_type: MessageType) -> Self {
        match msg_type {
            MessageType::ArbitraryMessage => vec![0x01],
            MessageType::FungibleToken => vec![0x02],
        }
    }
}

/// Message type used to bridge between Avail & other chains
#[derive(
Debug, Default, Clone, Eq, Encode, Decode, PartialEq, TypeInfo, Serialize, Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub message_type: MessageType,
    pub from: H256,
    pub to: H256,
    pub origin_domain: u32,
    pub destination_domain: u32,
    pub data: BoundedData,
    pub id: u64, // a global nonce that is incremented with each leaf
}

impl Message {
    pub fn abi_encode(self) -> Vec<u8> {
        encode(&[Token::Tuple(vec![
            Token::FixedBytes(self.message_type.into()),
            Token::FixedBytes(self.from.to_fixed_bytes().to_vec()),
            Token::FixedBytes(self.to.to_fixed_bytes().to_vec()),
            Token::Uint(ethabi::Uint::from(self.origin_domain)),
            Token::Uint(ethabi::Uint::from(self.destination_domain)),
            Token::Bytes(self.data.into()),
            Token::Uint(ethabi::Uint::from(self.id)),
        ])])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofResponse {
    pub data_proof: DataProofV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

#[derive(PartialEq, Debug)]
pub enum SubTrie {
    Left,
    Right,
}

/// Wrapper of `binary-merkle-tree::MerkleProof` with codec support.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DataProofV2 {
    /// Root hash of generated merkle tree.
    pub data_root: H256,
    /// Root hash of generated blob root.
    pub blob_root: H256,
    /// Root hash of generated bridge root.
    pub bridge_root: H256,
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

/// Conversion error from `binary-merkle-tree::MerkleProof`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DataProofV2TryFromError {
    /// Root cannot be converted into `H256`.
    #[error("Root cannot be converted into `H256`")]
    InvalidRoot,
    /// Leaf cannot be converted into `H256`.
    #[error("Leaf cannot be converted into `H256`")]
    InvalidLeaf,
    /// The given index of proofs cannot be converted into `H256`.
    #[error("Proof at {0} cannot be converted into `H256`")]
    InvalidProof(usize),
    /// Number of leaves overflowed.
    #[error("Number of leaves overflowed")]
    OverflowedNumberOfLeaves,
    /// Number of leaves must be greater than zero.
    #[error("Number of leaves cannot be zero")]
    InvalidNumberOfLeaves,
    /// Leaf index overflowed.
    #[error("Leaf index overflowed")]
    OverflowedLeafIndex,
    /// Leaf index overflowed or invalid (greater or equal to `number_of_leaves`)
    #[error("Leaf index is invalid")]
    InvalidLeafIndex,
}

#[cfg(feature = "runtime")]
impl<H, T> core::convert::TryFrom<(&MerkleProof<H, T>, H256, SubTrie)> for DataProofV2
    where
        T: AsRef<[u8]>,
        H: PartialEq + Eq + AsRef<[u8]>,
{
    type Error = DataProofV2TryFromError;

    fn try_from(
        merkle_proof_data: (&MerkleProof<H, T>, H256, SubTrie),
    ) -> Result<Self, Self::Error> {
        use crate::ensure;
        use DataProofV2TryFromError::*;

        use sp_io::hashing::keccak_256;

        let (merkle_proof, sub_trie_root, sub_trie) = merkle_proof_data;

        let root: H256 = <[u8; 32]>::try_from(merkle_proof.root.as_ref())
            .map_err(|_| InvalidRoot)?
            .into();

        let leaf: H256 = if sub_trie == SubTrie::Right {
            <[u8; 32]>::try_from(merkle_proof.leaf.as_ref())
                .map_err(|_| InvalidLeaf)?
                .into()
        } else {
            keccak_256(merkle_proof.leaf.as_ref()).into()
        };

        let proof = merkle_proof
            .proof
            .iter()
            .enumerate()
            .map(|(idx, proof)| {
                <[u8; 32]>::try_from(proof.as_ref())
                    .map_err(|_| InvalidProof(idx))
                    .map(H256::from)
            })
            .collect::<Result<Vec<H256>, _>>()?;
        let number_of_leaves =
            u32::try_from(merkle_proof.number_of_leaves).map_err(|_| OverflowedNumberOfLeaves)?;
        ensure!(number_of_leaves != 0, InvalidNumberOfLeaves);

        let leaf_index = u32::try_from(merkle_proof.leaf_index).map_err(|_| OverflowedLeafIndex)?;
        ensure!(leaf_index < number_of_leaves, InvalidLeafIndex);

        let data_root: H256;
        let blob_root: H256;
        let bridge_root: H256;
        match sub_trie {
            SubTrie::Right => {
                data_root = keccak256_concat!(root, sub_trie_root.as_bytes());
                bridge_root = sub_trie_root;
                blob_root = root;
            }
            SubTrie::Left => {
                data_root = keccak256_concat!(sub_trie_root.as_bytes(), root);
                blob_root = sub_trie_root;
                bridge_root = root;
            }
        }

        Ok(Self {
            proof,
            data_root,
            blob_root,
            bridge_root,
            leaf,
            number_of_leaves,
            leaf_index,
        })
    }
}

#[cfg(all(test, feature = "runtime"))]
mod test {
    use std::cmp::min;
    use ethabi::ethereum_types::U256;
    use frame_support::traits::DefensiveTruncateFrom;
    use hex_literal::hex;
    use crate::Keccak256;

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
    /// `DataProofV2`.
    fn merkle_proof_idx(
        leaf_index: usize,
        root: H256,
        sub_trie: SubTrie,
    ) -> (MerkleProof<H256, Vec<u8>>, H256, SubTrie) {
        let leaves = leaves();
        let index = min(leaf_index, leaves.len() - 1);
        let mut proof = binary_merkle_tree::merkle_proof::<Keccak256, _, _>(leaves, index);
        proof.leaf_index = leaf_index;

        (proof, root, sub_trie)
    }

    #[test]
    fn test_abi_encoding_with_serde() {
        // Original message
        let data = &[
            Token::FixedBytes(H256::zero().encode()),
            Token::Uint(U256::from(1991u128)),
        ];
        let encoded_data = BoundedVec::defensive_truncate_from(encode(data));
        let origin_message = Message {
            message_type: MessageType::FungibleToken,
            from: H256(hex!(
				"a285c87622a3ac392fb25454033f0c54f17675252d052ed581a97f64b731db12"
			)),
            to: H256(hex!(
				"0000000000000000000000007f5c02de7232b851000000000000000000000000"
			)),
            origin_domain: 1,
            destination_domain: 2,
            data: encoded_data,
            id: 0,
        };

        // Check abi encoding
        let encoded = origin_message.clone().abi_encode();
        let expected_origin_message_encoding = hex!("00000000000000000000000000000000000000000000000000000000000000200200000000000000000000000000000000000000000000000000000000000000a285c87622a3ac392fb25454033f0c54f17675252d052ed581a97f64b731db120000000000000000000000007f5c02de7232b8510000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c7").to_vec();
        assert_eq!(expected_origin_message_encoding, encoded);

        // check serialization
        let expected_serialized_message = "{\"messageType\":\"0x02\",\"from\":\"0xa285c87622a3ac392fb25454033f0c54f17675252d052ed581a97f64b731db12\",\"to\":\"0x0000000000000000000000007f5c02de7232b851000000000000000000000000\",\"originDomain\":1,\"destinationDomain\":2,\"data\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7,199],\"id\":0}";
        let serialized_message = serde_json::to_string(&origin_message).unwrap();
        assert_eq!(expected_serialized_message, serialized_message);

        // revert back to object
        let deserialized_message: Message = serde_json::from_slice(serialized_message.as_bytes()).unwrap();
        assert_eq!(origin_message.origin_domain, deserialized_message.origin_domain);
        assert_eq!(origin_message.message_type, deserialized_message.message_type);
        assert_eq!(origin_message.id, deserialized_message.id);
        assert_eq!(origin_message.to, deserialized_message.to);
        assert_eq!(origin_message.from, deserialized_message.from);
        assert_eq!(origin_message.data, deserialized_message.data);
        assert_eq!(origin_message.destination_domain, deserialized_message.destination_domain);
    }
}
