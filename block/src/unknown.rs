#![cfg(feature = "runtime")]

use crate::sp_std::{fmt, prelude::*};
use codec::{Decode, Encode};

use sp_debug_derive::RuntimeDebug;
use sp_runtime::traits::{Block as BlockT, NumberFor};

/// Something to identify a block.
#[derive(PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
pub enum BlockId<Block: BlockT> {
	/// Identify by block header hash.
	Hash(Block::Hash),
	/// Identify by block number.
	Number(NumberFor<Block>),
}

impl<Block: BlockT> BlockId<Block> {
	/// Create a block ID from a hash.
	pub const fn hash(hash: Block::Hash) -> Self {
		BlockId::Hash(hash)
	}

	/// Create a block ID from a number.
	pub const fn number(number: NumberFor<Block>) -> Self {
		BlockId::Number(number)
	}

	/// Check if this block ID refers to the pre-genesis state.
	pub fn is_pre_genesis(&self) -> bool {
		match self {
			BlockId::Hash(hash) => hash == &Default::default(),
			BlockId::Number(_) => false,
		}
	}

	/// Create a block ID for a pre-genesis state.
	pub fn pre_genesis() -> Self {
		BlockId::Hash(Default::default())
	}
}

impl<Block: BlockT> Copy for BlockId<Block> {}

#[cfg(feature = "std")]
impl<Block: BlockT> fmt::Display for BlockId<Block> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}
