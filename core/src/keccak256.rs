use hash_db::Hasher;
#[cfg(feature = "runtime")]
use {scale_info::TypeInfo, sp_debug_derive::RuntimeDebug};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Keccak 256 wrapper which supports `binary-merkle-tree::Hasher`.
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug, TypeInfo))]
#[cfg_attr(not(feature = "runtime"), derive(Debug))]
pub struct Keccak256 {}

impl Hasher for Keccak256 {
	type Out = primitive_types::H256;
	type StdHasher = hash256_std_hasher::Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(s: &[u8]) -> Self::Out {
		let keccak_out = avail_core_substrate::keccak_256(s);
		keccak_out.into()
	}
}

#[cfg(feature = "runtime")]
pub mod hash {
	use super::*;
	use crate::sp_std::vec::Vec;
	use sp_core::storage::StateVersion;
	use sp_trie::{LayoutV0, LayoutV1, TrieConfiguration as _};

	impl sp_runtime::traits::Hash for Keccak256 {
		type Output = primitive_types::H256;

		fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> Self::Output {
			match version {
				StateVersion::V0 => LayoutV0::<Keccak256>::trie_root(input),
				StateVersion::V1 => LayoutV1::<Keccak256>::trie_root(input),
			}
		}

		fn ordered_trie_root(input: Vec<Vec<u8>>, version: StateVersion) -> Self::Output {
			match version {
				StateVersion::V0 => LayoutV0::<Keccak256>::ordered_trie_root(input),
				StateVersion::V1 => LayoutV1::<Keccak256>::ordered_trie_root(input),
			}
		}
	}
}

#[cfg(feature = "runtime")]
#[allow(unused_imports)]
pub use hash::*;
