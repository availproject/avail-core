#![cfg(feature = "runtime")]

use super::super::traits_runtime::ExtendedHeader;
use super::{Header, HeaderExtension};
use primitive_types::H256;
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use sp_runtime::Digest;
use sp_runtime_interface::pass_by::{Codec as PassByCodecImpl, PassBy};

impl PassBy for Header {
	type PassBy = PassByCodecImpl<Header>;
}

impl HeaderT for Header {
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type Number = u32;

	fn number(&self) -> &Self::Number {
		&self.number
	}

	fn set_number(&mut self, num: Self::Number) {
		self.number = num
	}

	fn extrinsics_root(&self) -> &Self::Hash {
		&self.extrinsics_root
	}

	fn set_extrinsics_root(&mut self, root: Self::Hash) {
		self.extrinsics_root = root
	}

	fn state_root(&self) -> &Self::Hash {
		&self.state_root
	}

	fn set_state_root(&mut self, root: Self::Hash) {
		self.state_root = root
	}

	fn parent_hash(&self) -> &Self::Hash {
		&self.parent_hash
	}

	fn set_parent_hash(&mut self, hash: Self::Hash) {
		self.parent_hash = hash
	}

	fn digest(&self) -> &Digest {
		&self.digest
	}

	fn digest_mut(&mut self) -> &mut Digest {
		&mut self.digest
	}

	fn new(
		number: Self::Number,
		extrinsics_root: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
	) -> Self {
		Self {
			number,
			parent_hash,
			state_root,
			digest,
			extrinsics_root,
			extension: Default::default(),
		}
	}
}

impl ExtendedHeader for Header {
	type Extension = HeaderExtension;

	/// Creates new header.
	fn new(
		n: Self::Number,
		extrinsics: H256,
		state: H256,
		parent: H256,
		digest: Digest,
		extension: HeaderExtension,
	) -> Self {
		Header::new(n, extrinsics, state, parent, digest, extension)
	}

	fn extension(&self) -> &HeaderExtension {
		&self.extension
	}

	fn set_extension(&mut self, extension: HeaderExtension) {
		self.extension = extension;
	}
}
