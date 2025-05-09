#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::arithmetic_side_effects)]

#[cfg(feature = "std")]
pub mod com;
#[cfg(any(feature = "std", feature = "serde"))]
pub mod gridgen;
#[cfg(feature = "std")]
pub mod testnet;

pub mod couscous;
pub mod metrics;

// Exporting Dust Plonk, Dusk Bytes and poly_multiproof as pmp
#[cfg(feature = "std")]
pub use dusk_bytes;
pub use dusk_plonk::{self, commitment_scheme::kzg10::PublicParameters, prelude::BlsScalar};
pub use poly_multiproof as pmp;

use avail_core::{constants::kate::DATA_CHUNK_SIZE, BlockLengthColumns, BlockLengthRows};
use core::{
	convert::TryInto,
	num::{NonZeroU32, TryFromIntError},
};
use kate_recovery::matrix::Dimensions;
use poly_multiproof::ark_bls12_381::Fr;
use sp_arithmetic::traits::SaturatedConversion;
use sp_std::vec::Vec;
use static_assertions::const_assert_ne;
use thiserror_no_std::Error;
pub const LOG_TARGET: &str = "kate";
pub const U32_USIZE_ERR: &str = "`u32` cast to `usize` overflows, unsupported platform";
pub type Seed = [u8; 32];

#[cfg(feature = "std")]
pub use dusk_bytes::Serializable;

#[cfg(feature = "std")]
pub type M1NoPrecomp =
	pmp::method1::M1NoPrecomp<pmp::ark_bls12_381::Bls12_381, pmp::msm::blst::BlstMSMEngine>;

pub type ArkScalar = Fr;
pub mod config {
	use super::{BlockLengthColumns, BlockLengthRows};
	use core::num::NonZeroU16;

	pub const SCALAR_SIZE: usize = 32;
	pub const ROW_EXTENSION: NonZeroU16 = unsafe { NonZeroU16::new_unchecked(2) };
	pub const COL_EXTENSION: NonZeroU16 = NonZeroU16::MIN;
	pub const PROVER_KEY_SIZE: u32 = 48;
	pub const PROOF_SIZE: usize = 48;
	// MINIMUM_BLOCK_SIZE, MAX_BLOCK_ROWS and MAX_BLOCK_COLUMNS have to be a power of 2 because of the FFT functions requirements
	pub const MINIMUM_BLOCK_SIZE: usize = 128;
	pub const MAX_BLOCK_ROWS: BlockLengthRows = if cfg!(feature = "extended-columns") {
		BlockLengthRows(128)
	} else {
		BlockLengthRows(256)
	};
	pub const MAX_BLOCK_COLUMNS: BlockLengthColumns = if cfg!(feature = "extended-columns") {
		BlockLengthColumns(512)
	} else {
		BlockLengthColumns(256)
	};
	pub const MAXIMUM_BLOCK_SIZE: bool = cfg!(feature = "maximum-block-size");
}

/// Precalculate the g1_len of padding IEC 9797 1.
///
/// # NOTE
/// There is a unit test to ensure this formula match with the current
/// IEC 9797 1 algorithm we implemented. See `fn pad_iec_9797_1`
#[inline]
#[allow(clippy::arithmetic_side_effects)]
fn padded_len_of_pad_iec_9797_1(len: u32) -> u32 {
	let len_plus_one = len.saturating_add(1);
	let offset = (DATA_CHUNK_SIZE - (len_plus_one as usize % DATA_CHUNK_SIZE)) % DATA_CHUNK_SIZE;
	let offset: u32 = offset.saturated_into();

	len_plus_one.saturating_add(offset)
}

/// Calculates the padded len based of initial `len`.
#[allow(clippy::arithmetic_side_effects)]
pub fn padded_len(len: u32, chunk_size: NonZeroU32) -> u32 {
	let iec_9797_1_len = padded_len_of_pad_iec_9797_1(len);

	const_assert_ne!(DATA_CHUNK_SIZE, 0);
	debug_assert!(
		chunk_size.get() >= DATA_CHUNK_SIZE as u32,
		"`BlockLength.chunk_size` is valid by design .qed"
	);
	let diff_per_chunk = chunk_size.get() - DATA_CHUNK_SIZE as u32;
	let pad_to_chunk_extra = if diff_per_chunk != 0 {
		let chunks_count = iec_9797_1_len / DATA_CHUNK_SIZE as u32;
		chunks_count * diff_per_chunk
	} else {
		0
	};

	iec_9797_1_len + pad_to_chunk_extra
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BlockDimensions {
	rows: BlockLengthRows,
	cols: BlockLengthColumns,
	chunk_size: NonZeroU32,
	size: usize,
}

impl BlockDimensions {
	pub fn new(
		rows: BlockLengthRows,
		cols: BlockLengthColumns,
		chunk_size: NonZeroU32,
	) -> Option<Self> {
		let rows_cols = rows.0.checked_mul(cols.0)?;
		let size_u32 = rows_cols.checked_mul(chunk_size.get())?;
		let size = usize::try_from(size_u32).ok()?;

		Some(Self {
			rows,
			cols,
			chunk_size,
			size,
		})
	}

	#[inline]
	pub fn size(&self) -> usize {
		self.size
	}

	#[inline]
	pub fn rows(&self) -> BlockLengthRows {
		self.rows
	}

	#[inline]
	pub fn cols(&self) -> BlockLengthColumns {
		self.cols
	}
}

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum TryFromBlockDimensionsError {
	InvalidRowsOrColumns(#[from] TryFromIntError),
	InvalidDimensions,
}

impl TryInto<Dimensions> for BlockDimensions {
	type Error = TryFromBlockDimensionsError;

	fn try_into(self) -> Result<Dimensions, Self::Error> {
		Dimensions::new_from(self.rows.0, self.cols.0).ok_or(Self::Error::InvalidDimensions)
	}
}

// vim: set noet nowrap
