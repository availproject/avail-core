use core::num::NonZeroU32;
use std::{cmp::max, convert::TryFrom, num::TryFromIntError, sync::Mutex, time::Instant};
use thiserror_no_std::Error;

use avail_core::{
	const_generic_asserts::{USizeSafeCastToU32, UsizeEven, UsizeNonZero},
	data_lookup::v3::{DataLookup as DataLookupV3, Error as DataLookupError},
	ensure, AppId, BlockLengthColumns, BlockLengthRows,
};
use derive_more::Constructor;
use nalgebra::base::DMatrix;
use rand_chacha::rand_core::Error as ChaChaError;
use rayon::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use static_assertions::const_assert_eq;

use crate::{
	config::{
		COL_EXTENSION, MAXIMUM_BLOCK_SIZE, MINIMUM_BLOCK_SIZE, PROOF_SIZE, ROW_EXTENSION,
		SCALAR_SIZE,
	},
	metrics::Metrics,
	BlockDimensions, TryFromBlockDimensionsError,
};
use kate_recovery::commons::{ArkEvaluationDomain, ArkPublicParams, ArkScalar};
#[cfg(feature = "std")]
use kate_recovery::matrix::Dimensions;
use poly_multiproof::traits::KZGProof;
use poly_multiproof::{ark_poly::EvaluationDomain, traits::AsBytes};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Constructor, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cell {
	pub row: BlockLengthRows,
	pub col: BlockLengthColumns,
}

impl Cell {
	// Returns usize versions of row and col.
	// If an error is returned it means that we weren't able to
	// convert an u32 value to usize.
	#[allow(clippy::result_unit_err)]
	pub fn get_dimensions(&self) -> Result<(usize, usize), ()> {
		let Ok(row) = usize::try_from(self.row.0) else {
			return Err(());
		};
		let Ok(col) = usize::try_from(self.col.0) else {
			return Err(());
		};

		Ok((row, col))
	}
}

#[derive(Error, Debug)]
pub enum Error {
	// Keeping the removed errors placeholder for backwards compatibility
	PlonkErrorPlaceholder,
	DuskBytesErrorPlaceholder,
	MultiproofError(#[from] poly_multiproof::Error),
	CellLengthExceeded,
	BadHeaderHash,
	BlockTooBig,
	InvalidChunkLength,
	DimensionsMismatch,
	ZeroDimension,
	InvalidDimensionExtension,
	DomainSizeInvalid,
	InvalidDataLookup(#[from] DataLookupError),
	Rng(#[from] ChaChaError),
	/// The base grid width, before extension, does not fit cleanly into a domain for FFTs
	BaseGridDomainSizeInvalid(usize),
	/// The extended grid width does not fit cleanly into a domain for FFTs
	ExtendedGridDomainSizeInvalid(usize),
	IndexOutOfRange,
	ConversionFailed,
	InvalidMaxRows,
	InvalidMaxCols,
}

impl From<TryFromIntError> for Error {
	fn from(_: TryFromIntError) -> Self {
		Self::ZeroDimension
	}
}

impl From<TryFromBlockDimensionsError> for Error {
	fn from(_: TryFromBlockDimensionsError) -> Self {
		Self::BlockTooBig
	}
}

/// We cannot derive `PartialEq` because `PlonkError` does not support it in the current version.
/// and we only need to double check its discriminant for testing.
/// Only needed on tests by now.
#[cfg(test)]
impl PartialEq for Error {
	fn eq(&self, other: &Self) -> bool {
		std::mem::discriminant(self) == std::mem::discriminant(other)
	}
}

pub type XtsLayout = Vec<(AppId, u32)>;

pub fn get_block_dimensions<const CHUNK_SIZE: usize>(
	block_size: u32,
	max_rows: BlockLengthRows,
	max_cols: BlockLengthColumns,
) -> Result<BlockDimensions, Error> {
	// # SAFETY: `CHUNK_SIZE` is a constant, so it is always greater than 0 and even.
	// This assertions are important to ensure safety assumptions below.
	#[allow(clippy::let_unit_value)]
	let () = UsizeNonZero::<CHUNK_SIZE>::OK;
	#[allow(clippy::let_unit_value)]
	let () = UsizeEven::<CHUNK_SIZE>::OK;
	const_assert_eq!(MINIMUM_BLOCK_SIZE % 2, 0);

	// # SAFETY: `CHUNK_SIZE` is a constant always greater than 0 and its cast to `u32` is valid.
	#[allow(clippy::let_unit_value)]
	let () = USizeSafeCastToU32::<CHUNK_SIZE>::OK;
	let chunk_size_u32 = unsafe { NonZeroU32::new_unchecked(CHUNK_SIZE as u32) };

	// SAFETY: `max_rows` and `max_cols` must be a power of 2.
	// Otherwise block dimensions will be one row short, as the
	// row count equals `total_cells / max_cols1`.
	ensure!(max_rows.0.is_power_of_two(), Error::InvalidMaxRows);
	ensure!(max_cols.0.is_power_of_two(), Error::InvalidMaxCols);

	let max_block_dimensions =
		BlockDimensions::new(max_rows, max_cols, chunk_size_u32).ok_or(Error::BlockTooBig)?;
	let max_block_dimensions_size = max_block_dimensions.size();

	let block_size = usize::try_from(block_size)?;
	ensure!(block_size <= max_block_dimensions_size, Error::BlockTooBig);

	if block_size == max_block_dimensions_size || MAXIMUM_BLOCK_SIZE {
		return Ok(max_block_dimensions);
	}

	// Both row number and column number have to be a power of 2, because of the Plonk FFT constraints
	// Implicitly, if both of the assumptions above are correct, the total_cells number will also be a power of 2
	let nearest_power_2_size = block_size
		.checked_next_power_of_two()
		.unwrap_or(max_block_dimensions_size);
	let nearest_power_2_size = max(nearest_power_2_size, MINIMUM_BLOCK_SIZE);

	// # SAFETY: `CHUNK_SIZE` is greater than 0.
	// It removes the use of `f32::ceil`, like `(nearest_power_2_size as f32 / CHUNK_SIZE as f32).ceil() as u32`
	#[allow(clippy::arithmetic_side_effects)]
	let total_cells = nearest_power_2_size
		.checked_add(CHUNK_SIZE - 1)
		.ok_or(Error::BlockTooBig)?
		/ CHUNK_SIZE;
	let total_cells = u32::try_from(total_cells).map_err(|_| Error::ConversionFailed)?;

	// we must minimize number of rows, to minimize header size
	// (performance wise it doesn't matter)
	let nz_max_cols = NonZeroU32::new(max_cols.0).ok_or(Error::ZeroDimension)?;
	let (cols, rows) = if total_cells > max_cols.0 {
		(max_cols, BlockLengthRows(total_cells / nz_max_cols))
	} else {
		(BlockLengthColumns(total_cells), BlockLengthRows(1))
	};

	BlockDimensions::new(rows, cols, chunk_size_u32).ok_or(Error::BlockTooBig)
}

pub fn to_bls_scalar(chunk: &[u8]) -> Result<ArkScalar, Error> {
	let scalar_size_chunk =
		<[u8; SCALAR_SIZE]>::try_from(chunk).map_err(|_| Error::InvalidChunkLength)?;
	ArkScalar::from_bytes(&scalar_size_chunk).map_err(|_| Error::CellLengthExceeded)
}

fn make_dims(bd: BlockDimensions) -> Result<Dimensions, Error> {
	Dimensions::new_from(bd.rows.0, bd.cols.0).ok_or(Error::ZeroDimension)
}

/// Build extended data matrix, by columns.
/// We are using dusk plonk for erasure coding,
/// which is using roots of unity as evaluation domain for fft and ifft.
/// This means that extension factor has to be multiple of 2,
/// and that original data will be interleaved with erasure codes,
/// instead of being in first k chunks of a column.
///
/// `block` should be the raw data of a matrix, stored in row-major orientation.
#[cfg(feature = "parallel")]
pub fn par_extend_data_matrix<M: Metrics>(
	block_dims: BlockDimensions,
	block: &[u8],
	metrics: &M,
) -> Result<DMatrix<ArkScalar>, Error> {
	let start = Instant::now();
	let dims = make_dims(block_dims)?;
	let (ext_rows, _): (usize, usize) = dims
		.extend(ROW_EXTENSION, COL_EXTENSION)
		.ok_or(Error::InvalidDimensionExtension)?
		.into();
	let (rows, cols) = dims.into();

	// simple length with mod check would work...
	let chunk_size =
		usize::try_from(block_dims.chunk_size.get()).map_err(|_| Error::BlockTooBig)?;

	let chunks = block.par_chunks_exact(chunk_size);
	ensure!(chunks.remainder().is_empty(), Error::DimensionsMismatch);

	let scalars = chunks
		.into_par_iter()
		.map(to_bls_scalar)
		.collect::<Result<Vec<ArkScalar>, Error>>()?;

	let extended_column_eval_domain =
		ArkEvaluationDomain::new(ext_rows).ok_or(Error::InvalidDimensionExtension)?;
	let column_eval_domain = ArkEvaluationDomain::new(rows).ok_or(Error::DomainSizeInvalid)?; // rows_num = column_length

	// The data is currently row-major, so we need to put it into column-major
	let col_wise_scalars = DMatrix::from_row_iterator(rows, cols, scalars);

	let ext_columns_wise = (0..cols)
		.into_par_iter()
		.flat_map(|col| {
			let col_view = col_wise_scalars.column(col).data.into_slice();
			debug_assert_eq!(col_view.len(), rows);

			let coeffs = column_eval_domain.ifft(col_view);
			let extended_col = extended_column_eval_domain.fft(&coeffs);
			debug_assert_eq!(extended_col.len(), ext_rows);
			extended_col
		})
		.collect::<Vec<_>>();
	debug_assert_eq!(Some(ext_columns_wise.len()), cols.checked_mul(ext_rows));

	let ext_matrix = DMatrix::from_iterator(ext_rows, cols, ext_columns_wise);

	metrics.extended_block_time(start.elapsed());

	Ok(ext_matrix)
}

pub fn build_proof<M: Metrics>(
	public_params: &ArkPublicParams,
	block_dims: BlockDimensions,
	ext_data_matrix: &DMatrix<ArkScalar>,
	cells: &[Cell],
	metrics: &M,
) -> Result<Vec<u8>, Error> {
	let dims = make_dims(block_dims)?;
	let (ext_rows, ext_cols): (usize, usize) = dims
		.extend(ROW_EXTENSION, COL_EXTENSION)
		.ok_or(Error::InvalidDimensionExtension)?
		.into();
	let (_, cols): (usize, usize) = dims.into();

	const SPROOF_SIZE: usize = PROOF_SIZE + SCALAR_SIZE;

	let row_eval_domain = ArkEvaluationDomain::new(cols).ok_or(Error::DomainSizeInvalid)?;
	let row_dom_x_pts = row_eval_domain.elements().collect::<Vec<_>>();

	let mut result_bytes: Vec<u8> = vec![0u8; SPROOF_SIZE.saturating_mul(cells.len())];
	let row_dom_x_pts = &row_dom_x_pts;
	let total_start = Instant::now();

	// attempt to parallelly compute proof for all requested cells
	let cell_iter = cells
		.into_par_iter()
		.zip(result_bytes.par_chunks_exact_mut(SPROOF_SIZE));

	let locked_errors = Mutex::new(Vec::<Error>::new());

	let get_cell_row = |cell: &Cell| -> Result<(Vec<ArkScalar>, usize, usize), Error> {
		let r_index = usize::try_from(cell.row.0)?;
		if r_index >= ext_rows || cell.col >= block_dims.cols {
			return Err(Error::IndexOutOfRange);
		}
		let c_index = usize::try_from(cell.col.0)?;

		let get_ext_data_matrix =
			|j: usize| ext_data_matrix[r_index.saturating_add(j.saturating_mul(ext_rows))];

		// construct polynomial per extended matrix row
		#[cfg(feature = "parallel")]
		let row: Vec<ArkScalar> = {
			let mut row = Vec::with_capacity(ext_cols.checked_add(1).ok_or(Error::BlockTooBig)?);
			(0..ext_cols)
				.into_par_iter()
				.map(get_ext_data_matrix)
				.collect_into_vec(&mut row);
			row
		};
		#[cfg(not(feature = "parallel"))]
		let row = (0..ext_cols)
			.map(get_ext_data_matrix)
			.collect::<Vec<ArkScalar>>();

		Ok((row, r_index, c_index))
	};

	cell_iter.for_each(|(cell, res)| {
		let result = get_cell_row(cell);
		let Ok((row, r_index, c_index)) = result else {
			if let Ok(mut errors) = locked_errors.lock() {
				errors.push(result.expect_err("We checked before that this is OK."))
			}
			return;
		};

		// # SAFETY: "`interpolate` function panics if row length is not equal to
		// `block_dims.cols.next_power_of_two()`, which is true if `COL_EXTENSION` is 1.
		const_assert_eq!(COL_EXTENSION.get(), 1);
		// # SAFETY: `interpolate` function panics if the following debug assertion is not met,
		// so it would simplify the location of that error.
		debug_assert_eq!(row.len(), cols.next_power_of_two());

		let poly = row_eval_domain.ifft(&row);

		let witness = match public_params.compute_witness_polynomial(poly, row_dom_x_pts[c_index]) {
			Ok(w) => w,
			Err(e) => {
				if let Ok(mut errors) = locked_errors.lock() {
					errors.push(Error::MultiproofError(e));
				}
				return;
			},
		};

		let commitment_bytes = match public_params.open(witness) {
			Ok(commitment_to_witness) => match commitment_to_witness.to_bytes() {
				Ok(bytes) => bytes,
				Err(e) => {
					if let Ok(mut errors) = locked_errors.lock() {
						errors.push(Error::MultiproofError(e));
					}
					return;
				},
			},
			Err(e) => {
				if let Ok(mut errors) = locked_errors.lock() {
					errors.push(Error::MultiproofError(e));
				}
				return;
			},
		};

		let point_bytes = match ext_data_matrix
			[r_index.saturating_add(c_index.saturating_mul(ext_rows))]
		.to_bytes()
		{
			Ok(bytes) => bytes,
			Err(e) => {
				if let Ok(mut errors) = locked_errors.lock() {
					errors.push(Error::MultiproofError(e));
				}
				return;
			},
		};

		res[0..PROOF_SIZE].copy_from_slice(&commitment_bytes);
		res[PROOF_SIZE..].copy_from_slice(&point_bytes);
	});

	let cells_len = u32::try_from(cells.len()).unwrap_or(u32::MAX);
	metrics.proof_build_time(total_start.elapsed(), cells_len);

	if let Ok(mut errors) = locked_errors.lock() {
		if let Some(error) = errors.pop() {
			return Err(error);
		}
	}

	Ok(result_bytes)
}

#[cfg(feature = "std")]
fn get_row(m: &DMatrix<ArkScalar>, row_idx: usize) -> Vec<ArkScalar> {
	m.row(row_idx).iter().cloned().collect()
}

#[cfg(feature = "std")]
pub fn scalars_to_app_rows(
	id: AppId,
	lookup: &DataLookupV3,
	dimensions: Dimensions,
	matrix: &DMatrix<ArkScalar>,
) -> Vec<Option<Vec<u8>>> {
	let app_rows = kate_recovery::com::app_specific_rows(lookup, dimensions, id);
	dimensions
		.iter_extended_rows()
		.map(|i| {
			if app_rows.iter().any(|&row| row == i) {
				let row = get_row(matrix, i as usize);
				let maybe_bytes: Result<Vec<u8>, _> = row
					.iter()
					.map(ArkScalar::to_bytes)
					.collect::<Result<Vec<[u8; SCALAR_SIZE]>, _>>()
					.map(|chunks| chunks.into_iter().flatten().collect());
				match maybe_bytes {
					Ok(bytes) => Some(bytes),
					Err(e) => {
						log::error!("Failed to convert scalar at row {} to bytes: {:?}", i, e);
						None
					},
				}
			} else {
				None
			}
		})
		.collect()
}

#[cfg(feature = "std")]
fn row(
	data: &DMatrix<ArkScalar>,
	i: usize,
	cols: BlockLengthColumns,
	extended_rows: BlockLengthRows,
) -> Vec<ArkScalar> {
	let mut row = Vec::with_capacity(cols.0 as usize);
	(0..(cols.0 as usize).saturating_mul(extended_rows.0 as usize))
		.step_by(extended_rows.0 as usize)
		.for_each(|idx| row.push(data[i.saturating_add(idx)]));

	row
}

#[cfg(feature = "std")]
pub fn scalars_to_rows(
	rows: &[u32],
	dimensions: &Dimensions,
	data: &DMatrix<ArkScalar>,
) -> Vec<Option<Vec<u8>>> {
	let extended_rows = BlockLengthRows(dimensions.extended_rows());
	let cols = BlockLengthColumns(dimensions.cols().get() as u32);
	dimensions
		.iter_extended_rows()
		.map(|i| {
			if rows.contains(&i) {
				let scalars = row(data, i as usize, cols, extended_rows);
				let maybe_bytes: Result<Vec<u8>, _> = scalars
					.iter()
					.map(ArkScalar::to_bytes)
					.collect::<Result<Vec<[u8; SCALAR_SIZE]>, _>>()
					.map(|chunks| chunks.into_iter().flatten().collect());
				match maybe_bytes {
					Ok(bytes) => Some(bytes),
					Err(e) => {
						log::error!("Failed to convert scalars at row {} to bytes: {:?}", i, e);
						None
					},
				}
			} else {
				None
			}
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use crate::{gridgen::core::AsBytes, padded_len_of_pad_iec_9797_1, Seed};
	use avail_core::{
		const_generic_asserts::USizeGreaterOrEq,
		constants::kate::{CHUNK_SIZE, COMMITMENT_SIZE, DATA_CHUNK_SIZE},
		DataLookup,
	};
	use codec::{Compact, CompactLen, Decode};
	use core::num::NonZeroU16;
	use core::usize;
	use hex_literal::hex;
	use kate_recovery::proof::domain_points;
	use kate_recovery::{
		com::*,
		commitments,
		data::{self, DataCell, SingleCell},
		matrix::{Dimensions, Position},
		proof,
	};
	use rand::{prelude::IteratorRandom, Rng};
	use std::{convert::TryInto, iter::repeat};
	use test_case::test_case;

	use super::*;
	use crate::{
		com::{par_extend_data_matrix, BlockDimensions},
		couscous,
		gridgen::core::{EvaluationGrid, Multiproof},
		metrics::IgnoreMetrics,
		padded_len,
		pmp::{merlin::Transcript, traits::PolyMultiProofNoPrecomp},
	};
	use poly_multiproof::ark_bls12_381::Bls12_381;
	use poly_multiproof::traits::Committer;

	const TCHUNK_SIZE: usize = 32;
	const TCHUNK: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(TCHUNK_SIZE as u32) };

	type ArkCommitment = poly_multiproof::Commitment<Bls12_381>;
	type DataChunk = [u8; DATA_CHUNK_SIZE];

	#[inline]
	fn pad_with_zeroes(mut chunk: Vec<u8>, len: usize) -> Vec<u8> {
		chunk.resize(len, 0);
		chunk
	}

	fn pad_to_chunk<const CHUNK_SIZE: usize>(chunk: DataChunk) -> Vec<u8> {
		const_assert_eq!(DATA_CHUNK_SIZE, size_of::<DataChunk>());
		#[allow(clippy::let_unit_value)]
		let () = USizeGreaterOrEq::<CHUNK_SIZE, DATA_CHUNK_SIZE>::OK;

		let mut padded = chunk.to_vec();
		padded.resize(CHUNK_SIZE, 0);
		padded
	}

	fn pad_iec_9797_1(mut data: Vec<u8>) -> Vec<DataChunk> {
		let data_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
		let padded_size = padded_len_of_pad_iec_9797_1(data_len);
		data.resize(padded_size as usize, 0u8);

		// Transform into `DataChunk`.
		const_assert_eq!(DATA_CHUNK_SIZE, size_of::<DataChunk>());
		data.chunks(DATA_CHUNK_SIZE)
			.map(|e| e.try_into())
			.collect::<Result<Vec<DataChunk>, _>>()
			.expect("Const assertion ensures this transformation to `DataChunk`. qed")
	}

	// Generate a commitment
	fn commit(
		prover_key: &ArkPublicParams,
		domain: ArkEvaluationDomain,
		row: Vec<ArkScalar>,
	) -> Result<ArkCommitment, Error> {
		let poly = domain.ifft(&row);
		prover_key.commit(poly).map_err(Error::from)
	}

	#[cfg(not(feature = "maximum-block-size"))]
	#[test_case(0, 256, 256 => (1, 4) ; "block size zero")]
	#[test_case(11, 256, 256 => (1, 4) ; "below minimum block size")]
	#[test_case(300, 256, 256 => (1, 16) ; "regular case")]
	#[test_case(513, 256, 256 => (1, 32) ; "minimum overhead after 512")]
	#[test_case(8192, 256, 256 => (1, 256) ; "maximum cols")]
	#[test_case(8224, 256, 256 => (2, 256) ; "two rows")]
	#[test_case(2097152, 256, 256 => (256, 256) ; "max block size")]
	#[test_case(2097155, 256, 256 => panics "BlockTooBig" ; "too much data")]
	// newapi done
	fn test_get_block_dimensions(size: u32, rows: u32, cols: u32) -> (u32, u32) {
		let dims = get_block_dimensions::<TCHUNK_SIZE>(
			size,
			BlockLengthRows(rows),
			BlockLengthColumns(cols),
		)
		.unwrap();

		assert_eq!(dims.chunk_size.get(), TCHUNK_SIZE as u32);
		(dims.rows.0, dims.cols.0)
	}

	// newapi done
	#[test]
	fn test_extend_data_matrix() {
		let expected = [
			// Col 0
			hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e00"),
			hex!("bc1c6b8b4b02ca677b825ec9dace9aa706813f3ec47abdf9f03c680f4468555e"),
			hex!("7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a00"),
			hex!("c16115f73784be22106830c9bc6bbb469bf5026ee80325e403efe5ccc3f55016"),
			// Col 1
			hex!("1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d00"),
			hex!("db3b8aaa6a21e9869aa17de8f9edb9c625a05e5de399dc18105c872e6387745e"),
			hex!("9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b900"),
			hex!("e080341657a3dd412f874fe8db8ada65ba14228d07234403230e05ece2147016"),
			// Col 2
			hex!("3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c00"),
			hex!("fa5aa9c9894008a6b9c09c07190dd9e544bf7d7c02b9fb372f7ba64d82a6935e"),
			hex!("babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d800"),
			hex!("ff9f533576c2fc604ea66e07fba9f984d93341ac26426322422d240b02348f16"),
			// Col 3
			hex!("5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b00"),
			hex!("197ac8e8a85f27c5d8dfbb26382cf80464de9c9b21d81a574e9ac56ca1c5b25e"),
			hex!("d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f700"),
			hex!("1ebf725495e11b806dc58d261ac918a4f85260cb45618241614c432a2153ae16"),
		]
		.iter()
		.map(ArkScalar::from_bytes)
		.collect::<Result<Vec<_>, _>>()
		.expect("Invalid Expected result");
		let expected = DMatrix::from_iterator(4, 4, expected);

		let block_dims =
			BlockDimensions::new(BlockLengthRows(2), BlockLengthColumns(4), TCHUNK).unwrap();
		let chunk_size = usize::try_from(block_dims.chunk_size.get()).unwrap();
		let block = (0..=247)
			.collect::<Vec<u8>>()
			.chunks_exact(DATA_CHUNK_SIZE)
			.flat_map(|chunk| pad_with_zeroes(chunk.to_vec(), chunk_size))
			.collect::<Vec<u8>>();
		let ext_matrix = par_extend_data_matrix(block_dims, &block, &IgnoreMetrics {}).unwrap();
		assert_eq!(ext_matrix, expected);
	}

	#[test_case( 1..=29 => "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d0000" ; "chunk more than 3 values shorter")]
	#[test_case( 1..=30 => "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e00" ; "Chunk 2 values shorter")]
	#[test_case( 1..=31 => "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000000000000000000000000000000000000000000000000000" ; "Chunk 1 value shorter")]
	#[test_case( 1..=32 => "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000" ; "Chunk same size")]
	#[test_case( 1..=33 => "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210000000000000000000000000000000000000000000000000000000000" ; "Chunk 1 value longer")]
	#[test_case( 1..=34 => "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212200000000000000000000000000000000000000000000000000000000" ; "Chunk 2 value longer")]
	// newapi ignore
	fn test_padding<I: Iterator<Item = u8>>(block: I) -> String {
		let padded = pad_iec_9797_1(block.collect())
			.iter()
			.flat_map(|e| e.to_vec())
			.collect::<Vec<_>>();

		const_hex::encode(padded)
	}

	// returns the random cell positions by respecting the max col_percent % per column
	fn sampled_cells(dimensions: Dimensions, col_percent: u8) -> Vec<Position> {
		let mut rng = rand::thread_rng();
		let mut sampled_positions = vec![];
		for col in 0..dimensions.cols().get() {
			let total_cells = dimensions.rows().get();
			let sample_size = (col_percent as u32 * total_cells as u32) / 100;

			let col_positions: Vec<Position> = (0..total_cells)
				.map(|row| Position::new(row as u32, col))
				.choose_multiple(&mut rng, sample_size.try_into().unwrap());

			sampled_positions.extend(col_positions);
		}

		sampled_positions
	}

	#[test]
	fn test_row_padding_at_unified_grid() {
		// exact 3 rows
		let tx_size: usize = 3 * 256 * 31;
		let mut rng = rand::thread_rng();
		let data1: Vec<u8> = (0..tx_size).map(|_| rng.gen()).collect();
		let grid1 = EvaluationGrid::from_data(&data1, 256, 256, 256, Seed::default())
			.expect("Failed to create evaluation grid");

		let poly_grid1 = grid1
			.make_polynomial_grid()
			.map_err(|e| format!("Make polynomial grid failed: {e:?}"))
			.unwrap();

		// 3 * 256
		println!("grid1 dims: {:?}", grid1.dims());
		let public_params = couscous::multiproof_params();
		let extended_grid = poly_grid1
			.commitments(&public_params)
			.map_err(|e| format!("Commitments generation failed: {e:?}"))
			.unwrap();

		let mut commitments = Vec::new();
		for c in extended_grid.iter() {
			match c.to_bytes() {
				Ok(bytes) => commitments.extend(bytes),
				Err(e) => return println!("Failed to convert commitment to bytes: {e:?}"),
			}
		}
		println!("Commitments1 (hex): {}", const_hex::encode(&commitments));

		// exact 2 rows
		let tx_size: usize = 2 * 256 * 31;
		let data2: Vec<u8> = (0..tx_size).map(|_| rng.gen()).collect();
		let grid2 = EvaluationGrid::from_data(&data2, 256, 256, 256, Seed::default())
			.expect("Failed to create evaluation grid");

		let poly_grid2 = grid2
			.make_polynomial_grid()
			.map_err(|e| format!("Make polynomial grid failed: {e:?}"))
			.unwrap();

		// 2 * 256
		println!("grid2 dims: {:?}", grid2.dims());
		let extended_grid2 = poly_grid2
			.commitments(&public_params)
			.map_err(|e| format!("Commitments generation: {e:?}"))
			.unwrap();

		let mut commitments2 = Vec::new();
		for c in extended_grid2.iter() {
			match c.to_bytes() {
				Ok(bytes) => commitments2.extend(bytes),
				Err(e) => return println!("Failed to convert commitment to bytes: {e:?}"),
			}
		}
		println!("Commitments1 (hex): {}", const_hex::encode(&commitments2));
		// let grid1 = grid1
		// 	.extend_columns(NonZeroU16::new(2).expect("2>0"))
		// 	.unwrap();
		// let grid2 = grid2
		// 	.extend_columns(NonZeroU16::new(2).expect("2>0"))
		// 	.unwrap();
		// merge the grids
		let grids = vec![grid1, grid2];
		let merged_grid = EvaluationGrid::merge_with_padding(grids).unwrap();
		// 8 * 256
		println!("merged grid dims: {:?}", merged_grid.dims());
		// print 5th row of the merged grid
		println!(
			"merged grid row 5 {}",
			const_hex::encode(
				merged_grid
					.row(5)
					.unwrap()
					.iter()
					.map(|s| s.to_bytes().unwrap())
					.collect::<Vec<_>>()
					.concat()
			)
		);
		println!(
			"merged grid row 6 {}",
			const_hex::encode(
				merged_grid
					.row(6)
					.unwrap()
					.iter()
					.map(|s| s.to_bytes().unwrap())
					.collect::<Vec<_>>()
					.concat()
			)
		);
	}

	#[test]
	fn test_pre_generated_row() {
		// exact 3 rows
		let tx_size: usize = 3 * 256 * 31;
		let mut rng = rand::thread_rng();
		let data1: Vec<u8> = (0..tx_size).map(|_| rng.gen()).collect();
		let grid1 = EvaluationGrid::from_data(&data1, 256, 256, 256, Seed::default())
			.expect("Failed to create evaluation grid");

		let poly_grid1 = grid1
			.make_polynomial_grid()
			.map_err(|e| format!("Make polynomial grid failed: {e:?}"))
			.unwrap();

		// 3 * 256
		println!("grid1 dims: {:?}", grid1.dims());
		let public_params = couscous::multiproof_params();
		let comms = poly_grid1
			.commitments(&public_params)
			.map_err(|e| format!("Commitments generation failed: {e:?}"))
			.unwrap();

		let mut header_commitments = Vec::new();
		for c in comms.iter() {
			match c.to_bytes() {
				Ok(bytes) => header_commitments.extend(bytes),
				Err(e) => return println!("Failed to convert commitment to bytes: {e:?}"),
			}
		}
		// lets check & ensure the number of rows are in power  of 2
		let original_rows = comms.len();
		let padded_rows = original_rows.next_power_of_two();
		if padded_rows > original_rows {
			// we need to perform row padding using pregenrated rows
			let (_padded_row, padded_row_commitment) =
				crate::gridgen::core::get_pregenerated_row_and_commitment(256)
					.expect("lets hope, it works :)");

			header_commitments = header_commitments
				.into_iter()
				.chain(
					std::iter::repeat(padded_row_commitment)
						.take((padded_rows - original_rows) as usize)
						.flat_map(|x| x),
				)
				.collect();
		}

		let grids = vec![grid1];
		let uni_grid = EvaluationGrid::merge_with_padding(grids).unwrap();

		let poly = uni_grid.make_polynomial_grid().unwrap();
		let pol_comms = poly.commitments(&public_params).unwrap();
		let mut proof_comms: Vec<u8> = Vec::new();
		for c in pol_comms.iter() {
			match c.to_bytes() {
				Ok(bytes) => proof_comms.extend(bytes),
				Err(e) => return println!("Failed to convert commitment to bytes: {e:?}"),
			}
		}
		assert_eq!(header_commitments, proof_comms);
	}

	#[test]
	fn test_merge_grid() {
		// single full row
		let tx_size: usize = 256 * 32 - 256;
		let mut rng = rand::thread_rng();
		let data1: Vec<u8> = (0..tx_size).map(|_| rng.gen()).collect();
		let grid1 = EvaluationGrid::from_data(&data1, 256, 256, 256, Seed::default())
			.expect("Failed to create evaluation grid");

		let poly_grid1 = grid1
			.make_polynomial_grid()
			.map_err(|e| format!("Make polynomial grid failed: {e:?}"))
			.unwrap();

		println!("grid dims: {:?}", grid1.dims());
		let public_params = couscous::multiproof_params();
		let extended_grid = poly_grid1
			.extended_commitments(&public_params, 2)
			.map_err(|e| format!("Grid extension failed: {e:?}"))
			.unwrap();

		let mut commitments = Vec::new();
		for c in extended_grid.iter() {
			match c.to_bytes() {
				Ok(bytes) => commitments.extend(bytes),
				Err(e) => return println!("Failed to convert commitment to bytes: {e:?}"),
			}
		}
		println!("Commitments1 (hex): {}", const_hex::encode(&commitments));

		let data2: Vec<u8> = (0..tx_size).map(|_| rng.gen()).collect();
		let grid2 = EvaluationGrid::from_data(&data2, 256, 256, 256, Seed::default())
			.expect("Failed to create evaluation grid");

		let poly_grid2 = grid2
			.make_polynomial_grid()
			.map_err(|e| format!("Make polynomial grid failed: {e:?}"))
			.unwrap();

		println!("grid dims: {:?}", grid2.dims());
		let public_params = couscous::multiproof_params();
		let extended_grid2 = poly_grid2
			.extended_commitments(&public_params, 2)
			.map_err(|e| format!("Grid extension failed: {e:?}"))
			.unwrap();

		let mut commitments2 = Vec::new();
		for c in extended_grid2.iter() {
			match c.to_bytes() {
				Ok(bytes) => commitments2.extend(bytes),
				Err(e) => return println!("Failed to convert commitment to bytes: {e:?}"),
			}
		}
		println!("Commitments1 (hex): {}", const_hex::encode(&commitments2));
		let grid1 = grid1
			.extend_columns(NonZeroU16::new(2).expect("2>0"))
			.unwrap();
		let grid2 = grid2
			.extend_columns(NonZeroU16::new(2).expect("2>0"))
			.unwrap();
		// merge the grids
		let grids = vec![grid1, grid2];
		let merged_grid = EvaluationGrid::merge(grids).unwrap();
		println!("merged grid dims: {:?}", merged_grid.dims());
		commitments.extend(commitments2);
		println!(
			"merged commitments (hex): {}",
			const_hex::encode(&commitments)
		);
		let commitments_vec =
			commitments::from_slice(&commitments).expect("Failed to parse commitments");

		let extended_poly_grid = merged_grid
			.make_polynomial_grid()
			.map_err(|e| format!("Make polynomial grid failed: {e:?}"))
			.unwrap();
		println!("extended grid dims: {:?}", merged_grid.dims());
		for col in 0..merged_grid.dims().cols().get() {
			// Checking only for a single row
			let row = 0u32;
			let data = merged_grid
				.get(row as usize, col as usize)
				.expect("Missing cell in grid")
				.to_bytes()
				.expect("Data serialization failed");

			let cell = Cell::new(BlockLengthRows(row), BlockLengthColumns(col as u32));
			let proof = extended_poly_grid
				.proof(&public_params, &cell)
				.expect("Proof generation failed")
				.to_bytes()
				.expect("Proof serialization failed");

			let cell_proof: [u8; 80] = {
				let mut buffer = [0u8; 80];
				buffer[..proof.len()].copy_from_slice(&proof);
				buffer[proof.len()..].copy_from_slice(&data);
				buffer
			};

			// println!(
			// 	"Cell index: ({}, {}), Cell bytes (hex): {}",
			// 	row,
			// 	col,
			// 	hex::encode(&cell_proof)
			// );

			let position = Position {
				row,
				col: col.try_into().expect("Column conversion failed"),
			};

			let cell = SingleCell {
				position,
				content: cell_proof,
			};

			let commitment = commitments_vec[row as usize];
			let verification =
				proof::verify_v2(&public_params, merged_grid.dims(), &commitment, &cell);
			assert!(
				verification.is_ok(),
				"Verification failed for cell ({}, {}): {:?}",
				row,
				col,
				verification.err()
			);
			assert!(
				verification.unwrap(),
				"Verification returned false for cell ({}, {})",
				row,
				col
			);
		}
	}

	fn build_extrinsics(lens: &[usize]) -> Vec<Vec<u8>> {
		lens.iter()
			.map(|len| repeat(b'a').take(*len).collect::<Vec<_>>())
			.collect()
	}

	fn padded_len_group(lens: &[u32], chunk_size: u32) -> u32 {
		let chunk_size = NonZeroU32::new(chunk_size).unwrap();
		lens.iter().map(|len| padded_len(*len, chunk_size)).sum()
	}

	#[test_case( build_extrinsics(&[5,30,31]) => padded_len_group(&[5,30,31], 32) ; "Single chunk per ext")]
	#[test_case( build_extrinsics(&[5,30,32]) => padded_len_group(&[5,30,32], 32) ; "Extra chunk per ext")]
	#[test_case( build_extrinsics(&[5,64,120]) => padded_len_group(&[5,64,120], 32) ; "Extra chunk 2 per ext")]
	#[test_case( build_extrinsics(&[]) => padded_len_group(&[], 32) ; "Empty chunk list")]
	#[test_case( build_extrinsics(&[4096]) => padded_len_group(&[4096], 32) ; "4K chunk")]
	fn test_padding_len(extrinsics: Vec<Vec<u8>>) -> u32 {
		let sum = extrinsics
			.into_iter()
			.flat_map(pad_iec_9797_1)
			.map(|chunk| pad_to_chunk::<TCHUNK_SIZE>(chunk).len())
			.sum::<usize>();
		u32::try_from(sum).unwrap_or(u32::MAX)
	}

	#[test_case( ([1,1,1,1]).to_vec(); "All values are non-zero but same")]
	#[test_case( ([0,0,0,0]).to_vec(); "All values are zero")]
	#[test_case( ([0,5,2,1]).to_vec(); "All values are different")]
	fn test_zero_deg_poly_commit(row_values: Vec<u8>) {
		// There are two main cases that generate a zero degree polynomial. One is for data that is non-zero, but the same.
		// The other is for all-zero data. They differ, as the former yields a polynomial with one coefficient, and latter generates zero coefficients.
		let len = row_values.len();
		// let public_params = testnet::public_params(len);
		// let public_params = couscous::public_params();
		let pmp_pp = couscous::multiproof_params();
		// let (prover_key, _) = public_params.trim(len).map_err(Error::from).unwrap();
		let row_eval_domain = ArkEvaluationDomain::new(len).unwrap();

		let row = row_values
			.iter()
			.map(|val| {
				let mut value = [0u8; 32];
				let v = value.last_mut().unwrap();
				*v = *val;
				ArkScalar::from_bytes(&value).unwrap()
			})
			.collect::<Vec<_>>();

		assert_eq!(row.len(), len);
		println!("Row: {:?}", row);
		let commitment: [u8; COMMITMENT_SIZE] = commit(&pmp_pp, row_eval_domain, row.clone())
			.map(|com| com.to_bytes().unwrap())
			.unwrap();
		println!("Commitment: {commitment:?}");

		// We artificially extend the matrix by doubling values, this is not proper erasure coding.
		let ext_m =
			DMatrix::from_row_iterator(1, row.len() * 2, row.into_iter().flat_map(|e| vec![e, e]));

		let rows: u16 = len.try_into().expect("rows length should be valid `u16`");
		let metrics = IgnoreMetrics {};

		for col in 0..rows {
			// Randomly chosen cell to prove, probably should test all of them
			let cell = Cell {
				col: BlockLengthColumns(col.into()),
				row: BlockLengthRows(0),
			};
			let proof = build_proof(
				&pmp_pp,
				BlockDimensions::new(BlockLengthRows(1), BlockLengthColumns(4), TCHUNK).unwrap(),
				&ext_m,
				&[cell],
				&metrics,
			)
			.unwrap();
			println!("Proof: {proof:?}");

			assert_eq!(proof.len(), 80);

			let dims = Dimensions::new(1, 4).unwrap();
			let cell = data::SingleCell {
				position: Position { row: 0, col },
				content: proof.try_into().unwrap(),
			};
			let verification = proof::verify_v2(&pmp_pp, dims, &commitment, &cell);
			assert!(verification.is_ok());
			assert!(verification.unwrap())
		}
	}

	#[test_case( r#"{ "row": 42, "col": 99 }"# => Cell::new(BlockLengthRows(42), BlockLengthColumns(99)) ; "Simple" )]
	#[test_case( r#"{ "row": 4294967295, "col": 99 }"# => Cell::new(BlockLengthRows(4_294_967_295),BlockLengthColumns(99)) ; "Max row" )]
	// newapi ignore
	fn serde_block_length_types_untagged(data: &str) -> Cell {
		serde_json::from_str(data).unwrap()
	}

	#[test]
	fn cell_get_dimensions_returns_the_correct_values() {
		let row = 20;
		let col = 25;
		let cell = Cell {
			row: BlockLengthRows::new(row),
			col: BlockLengthColumns::new(col),
		};

		let expected_row = usize::try_from(row).unwrap();
		let expected_col = usize::try_from(col).unwrap();
		let (actual_row, actual_col) = cell.get_dimensions().unwrap();
		assert_eq!(actual_row, expected_row);
		assert_eq!(actual_col, expected_col);
	}

	#[test]
	fn test_data_reconstruction() {
		let mut rng = rand::thread_rng();

		// 4 rows
		let tx_size = 3 * 31 * 256;
		let original_data: Vec<u8> = (0..tx_size).map(|_| rng.gen()).collect();

		let seed = Seed::default();
		let grid = EvaluationGrid::from_data(&original_data, 4, 256, 256, seed)
			.expect("Failed to create evaluation grids");
		println!("orginal grid dims: {:?}", grid.dims());
		let extended_grid = grid
			.extend_columns(NonZeroU16::new(2).expect("2>0"))
			.expect("Failed to extend columns");
		println!("extended grid dims: {:?}", extended_grid.dims());
		let mut app_rows: Vec<(AppId, usize)> = Vec::new();
		app_rows.push((AppId(2), grid.dims().height()));
		let lookup = DataLookup::from_id_and_len_iter(app_rows.into_iter()).unwrap();

		// if any of the column has less than 50% of cells, that column wont be able to reconstructed
		let sampled_cells = sampled_cells(extended_grid.dims(), 50);
		println!("Got {} random cells", sampled_cells.len());
		let data_cells: Vec<_> = sampled_cells
			.iter()
			.map(|position| {
				let data = extended_grid
					.get(position.row as usize, position.col)
					.expect("Every valid cell position should have a data")
					.to_bytes()
					.expect("ArkScalar to byte conversion should work")
					.to_vec();
				DataCell {
					data,
					position: *position,
				}
			})
			.collect();

		// OPTION 1
		let rows = reconstruct_rows(grid.dims(), data_cells.clone()).unwrap();
		// flatten the rows into vec<u8>
		let padded_data: Vec<u8> = rows.concat();
		let reconstructed_data = {
			assert!(padded_data.len() % CHUNK_SIZE == 0, "corrupt data");
			let encoded_data = padded_data
				.chunks(CHUNK_SIZE)
				.flat_map(|chunk| &chunk[0..DATA_CHUNK_SIZE])
				.cloned()
				.collect::<Vec<u8>>();
			let mut encoded_slice = &encoded_data[..];
			let decoded = Vec::<u8>::decode(&mut encoded_slice).unwrap();
			decoded
		};
		assert_eq!(original_data, reconstructed_data);

		// OPTION 2
		let reconstruct =
			reconstruct_extrinsics_data(&lookup, grid.dims(), data_cells.clone()).unwrap();
		let (_app_id, reconstructed_data) = &reconstruct[0];
		assert_eq!(original_data, reconstructed_data.concat());

		// OPTION 3
		let reconstructed_data =
			reconstruct_app_extrinsic_data(AppId(2), &lookup, grid.dims(), data_cells).unwrap();
		assert_eq!(original_data, reconstructed_data.concat());
	}

	fn compact_len(value: &u32) -> Option<u32> {
		let len = Compact::<u32>::compact_len(value);
		len.try_into().ok()
	}

	#[test]
	fn test_multiproof_verification_from_data() {
		let rows: u16 = 1;
		let cols: u16 = 16;
		let target_dims = Dimensions::new_from(1, 8).unwrap();

		// Compute transaction size
		let tx_size: u32 = rows as u32 * cols as u32 * 31;
		let encoding_overhead = compact_len(&tx_size).unwrap();
		let tx_size = tx_size.saturating_sub(encoding_overhead) as usize;

		// Generate random data
		let mut rng = rand::thread_rng();
		let data: Vec<u8> = (0..tx_size).map(|_| rng.gen()).collect();
		let seed = Seed::default();

		let pp = crate::couscous::multiproof_params();

		let points = domain_points(cols.into()).unwrap();
		let grid =
			EvaluationGrid::from_data(&data, cols.into(), cols.into(), rows.into(), seed).unwrap();
		println!("original grid dimension: {:#?}", grid.dims());
		println!("target grid dimension: {:#?}", target_dims);
		let polys = grid.make_polynomial_grid().unwrap();
		let commitments = polys.commitments(&pp).unwrap();

		for row in 0..target_dims.rows().get() {
			for col in 0..target_dims.cols().get() {
				println!("Testing multiproof for cell ({}, {})", row, col);
				let Multiproof {
					proof,
					evals,
					block,
				} = polys
					.multiproof(
						&pp,
						&Cell::new(BlockLengthRows(row.into()), BlockLengthColumns(col.into())),
						&grid,
						target_dims,
					)
					.unwrap();
				println!("mp_block: {:#?}", block);
				let verified = PolyMultiProofNoPrecomp::verify(
					&pp,
					&mut Transcript::new(b"avail-mp"),
					&commitments,
					&points[block.start_x..block.end_x],
					&evals,
					&proof,
				)
				.unwrap();

				assert!(
					verified,
					"Multiproof verification failed for cell ({}, {})",
					row, col
				);
			}
		}
	}
}
