#![cfg(feature = "runtime")]

use crate::sp_std::fmt::Debug;
use codec::Codec;
use scale_info::TypeInfo;
use sp_runtime::traits::Block;
use sp_runtime::{
	generic::Digest,
	traits::{Header, MaybeSerialize},
};

/// Extended Block trait that extends substrate primitive Block to include ExtendedHeader in the header
pub trait ExtendedBlock: Block<Header = Self::ExtHeader> {
	type ExtHeader: ExtendedHeader;
}

/// Extended header access
pub trait ExtendedHeader: Header {
	type Extension: Clone + Send + Sync + Codec + Eq + MaybeSerialize + Debug + TypeInfo + 'static;

	/// Creates new header.
	fn new(
		number: Self::Number,
		extrinsics_root: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
		extension: Self::Extension,
	) -> Self;

	fn extension(&self) -> &Self::Extension;

	fn set_extension(&mut self, extension: Self::Extension);
}
