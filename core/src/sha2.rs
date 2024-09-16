#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sp_core::Hasher;
#[cfg(feature = "runtime")]
use {scale_info::TypeInfo, sp_debug_derive::RuntimeDebug};

/// Sha2 256 wrapper which supports `binary-merkle-tree::Hasher`.
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug, TypeInfo))]
pub struct ShaTwo256 {}

impl Hasher for ShaTwo256 {
	type Out = primitive_types::H256;
	type StdHasher = hash256_std_hasher::Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(s: &[u8]) -> Self::Out {
		let sha2_out = avail_core_substrate::sha2_256(s);
		sha2_out.into()
	}
}

#[cfg(feature = "runtime")]
pub mod hash {
	use super::*;
	use crate::sp_std::vec::Vec;
	use sp_core::storage::StateVersion;
	use sp_trie::{LayoutV0, LayoutV1, TrieConfiguration as _};

	impl sp_runtime::traits::Hash for ShaTwo256 {
		type Output = primitive_types::H256;

		fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> Self::Output {
			match version {
				StateVersion::V0 => LayoutV0::<ShaTwo256>::trie_root(input),
				StateVersion::V1 => LayoutV1::<ShaTwo256>::trie_root(input),
			}
		}

		fn ordered_trie_root(input: Vec<Vec<u8>>, version: StateVersion) -> Self::Output {
			match version {
				StateVersion::V0 => LayoutV0::<ShaTwo256>::ordered_trie_root(input),
				StateVersion::V1 => LayoutV1::<ShaTwo256>::ordered_trie_root(input),
			}
		}
	}
}

#[cfg(feature = "runtime")]
#[allow(unused_imports)]
pub use hash::*;
