#![cfg(feature = "runtime")]

use super::header::Header;
use super::traits_runtime::ExtendedBlock;
use crate::sp_std::prelude::*;
use codec::{Codec, Encode};
use sp_runtime::traits::{self, Block as BlockT, MaybeSerializeDeserialize, Member};

use super::bock::DaBlock;

impl<Extrinsic> traits::HeaderProvider for DaBlock<Extrinsic>
where
	Extrinsic: Codec,
{
	type HeaderT = Header;
}

impl<Extrinsic> BlockT for DaBlock<Extrinsic>
where
	Extrinsic: Member + Codec + MaybeSerializeDeserialize + traits::Extrinsic,
{
	type Extrinsic = Extrinsic;
	type Header = Header;
	type Hash = <Self::Header as traits::Header>::Hash;

	fn header(&self) -> &Self::Header {
		&self.header
	}
	fn extrinsics(&self) -> &[Self::Extrinsic] {
		&self.extrinsics[..]
	}
	fn deconstruct(self) -> (Self::Header, Vec<Self::Extrinsic>) {
		(self.header, self.extrinsics)
	}
	fn new(header: Self::Header, extrinsics: Vec<Self::Extrinsic>) -> Self {
		DaBlock { header, extrinsics }
	}
	fn encode_from(header: &Self::Header, extrinsics: &[Self::Extrinsic]) -> Vec<u8> {
		(header, extrinsics).encode()
	}
}

impl<Extrinsic> ExtendedBlock for DaBlock<Extrinsic>
where
	Extrinsic: Member + Codec + traits::Extrinsic + MaybeSerializeDeserialize,
{
	type ExtHeader = Header;
}
