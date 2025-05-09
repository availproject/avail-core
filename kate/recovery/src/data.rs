use crate::matrix::{Dimensions, Position, RowIndex};
use codec::{Decode, Encode};
use core::convert::TryInto;
use derive_more::Constructor;
use sp_std::{collections::btree_map::BTreeMap, convert::TryFrom, mem, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
extern crate alloc;
#[cfg(target_arch = "wasm32")]
use alloc::string::String;

/// Position and data of a cell in extended matrix
#[derive(Default, Debug, Clone, Constructor)]
pub struct DataCell {
	/// SingleCell's position
	pub position: Position,
	/// SingleCell's data
	pub data: [u8; 32],
}

/// Position and content of a cell in extended matrix
#[derive(Debug, Clone, Constructor)]
pub struct SingleCell {
	/// Cell's position
	pub position: Position,
	/// Cell's data
	pub content: [u8; 80],
}

impl SingleCell {
	#[cfg(any(target_arch = "wasm32", feature = "std"))]
	pub fn reference(&self, block: u32) -> String {
		self.position.reference(block)
	}

	pub fn data(&self) -> [u8; 32] {
		self.content[48..].try_into().expect("content is 80 bytes")
	}

	pub fn proof(&self) -> [u8; 48] {
		self.content[..48].try_into().expect("content is 80 bytes")
	}
}

#[derive(Debug, Clone, Constructor)]
pub struct MultiProofCell {
	pub position: Position,
	pub scalars: Vec<[u64; 4]>,
	pub proof: [u8; 48],
	pub gcell_block: GCellBlock,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GCellBlock {
	pub start_x: u32,
	pub start_y: u32,
	pub end_x: u32,
	pub end_y: u32,
}

impl GCellBlock {
	pub const GCELL_BLOCK_SIZE: usize = mem::size_of::<GCellBlock>();

	pub fn to_bytes(&self) -> Vec<u8> {
		let mut buf = Vec::with_capacity(16);
		buf.extend(&self.start_x.to_le_bytes());
		buf.extend(&self.start_y.to_le_bytes());
		buf.extend(&self.end_x.to_le_bytes());
		buf.extend(&self.end_y.to_le_bytes());
		buf
	}

	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		if bytes.len() != Self::GCELL_BLOCK_SIZE {
			return Err("GCellBlock must be exactly 16 bytes");
		}

		let start_x = bytes
			.get(0..4)
			.and_then(|b| b.try_into().ok())
			.map(u32::from_le_bytes);
		let start_y = bytes
			.get(4..8)
			.and_then(|b| b.try_into().ok())
			.map(u32::from_le_bytes);
		let end_x = bytes
			.get(8..12)
			.and_then(|b| b.try_into().ok())
			.map(u32::from_le_bytes);
		let end_y = bytes
			.get(12..16)
			.and_then(|b| b.try_into().ok())
			.map(u32::from_le_bytes);

		match (start_x, start_y, end_x, end_y) {
			(Some(start_x), Some(start_y), Some(end_x), Some(end_y)) => Ok(Self {
				start_x,
				start_y,
				end_x,
				end_y,
			}),
			_ => Err("Failed to convert bytes to GCellBlock"),
		}
	}
}

impl MultiProofCell {
	pub const PROOF_BYTE_LEN: usize = mem::size_of::<[u8; 48]>();
	pub const SCALAR_COUNT_LEN: usize = mem::size_of::<u32>();
	pub const SCALAR_BYTE_LEN: usize = mem::size_of::<[u8; 32]>();
	pub const LIMBS_PER_SCALAR: usize = 4;
	pub const BYTES_PER_LIMB: usize = mem::size_of::<u64>();
	pub const BYTES_PER_SCALAR: usize = Self::LIMBS_PER_SCALAR * Self::BYTES_PER_LIMB;

	#[cfg(any(target_arch = "wasm32", feature = "std"))]
	pub fn reference(&self, block: u32) -> String {
		self.position.reference(block)
	}

	pub fn from_bytes(position: Position, bytes: &[u8]) -> Result<Self, &'static str> {
		let min_required_len =
			Self::PROOF_BYTE_LEN + GCellBlock::GCELL_BLOCK_SIZE + Self::SCALAR_COUNT_LEN;
		if bytes.len() < min_required_len {
			return Err("Input too short to be a valid MultiProofCell");
		}

		// 1. Parse fixed parts
		let (proof_bytes, rest) = bytes.split_at(Self::PROOF_BYTE_LEN);
		let proof: [u8; 48] = proof_bytes.try_into().map_err(|_| "Invalid proof bytes")?;

		let (gcell_block_bytes, rest) = rest.split_at(GCellBlock::GCELL_BLOCK_SIZE);
		let gcell_block = GCellBlock::from_bytes(gcell_block_bytes)?;

		let (scalar_count_bytes, rest) = rest.split_at(Self::SCALAR_COUNT_LEN);
		let scalar_count = scalar_count_bytes
			.get(..4)
			.and_then(|b| b.try_into().ok())
			.map(u32::from_le_bytes)
			.ok_or("Failed to read scalar count")? as usize;

		let expected_scalar_len = scalar_count * Self::SCALAR_BYTE_LEN;
		if rest.len() != expected_scalar_len {
			return Err("Scalar data length mismatch");
		}

		// 2. Parse scalars
		let mut scalars = Vec::with_capacity(scalar_count);
		for chunk in rest.chunks_exact(Self::SCALAR_BYTE_LEN) {
			let mut scalar = [0u64; 4];
			for (i, limb_bytes) in chunk.chunks_exact(Self::BYTES_PER_LIMB).enumerate() {
				if i >= Self::LIMBS_PER_SCALAR {
					return Err("Too many limbs in scalar");
				}
				scalar[i] = limb_bytes
					.try_into()
					.ok()
					.map(u64::from_be_bytes)
					.ok_or("Failed to decode scalar limb")?;
			}
			scalars.push(scalar);
		}

		Ok(Self {
			position,
			proof,
			gcell_block,
			scalars,
		})
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		let proof_bytes: Vec<u8> = self.proof.into();
		let gcell_block_bytes = self.gcell_block.to_bytes();
		let scalar_count = self.scalars.len();

		let total_size = Self::PROOF_BYTE_LEN
			+ gcell_block_bytes.len()
			+ Self::SCALAR_COUNT_LEN
			+ scalar_count * Self::SCALAR_BYTE_LEN;

		let mut content = Vec::with_capacity(total_size);
		content.extend_from_slice(&proof_bytes);
		content.extend_from_slice(&gcell_block_bytes);
		content.extend_from_slice(&(scalar_count as u32).to_le_bytes());
		content.extend_from_slice(&self.data());

		content
	}

	pub fn data(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.scalars.len() * Self::BYTES_PER_SCALAR);

		for scalar in &self.scalars {
			for &limb in scalar {
				bytes.extend_from_slice(&limb.to_be_bytes());
			}
		}

		bytes
	}

	pub fn proof(&self) -> [u8; 48] {
		self.proof
	}
}

#[derive(Debug, Clone)]
pub enum Cell {
	SingleCell(SingleCell),
	MultiProofCell(MultiProofCell),
}

impl Cell {
	#[cfg(any(target_arch = "wasm32", feature = "std"))]
	pub fn reference(&self, block: u32) -> String {
		match self {
			Cell::SingleCell(cell) => cell.reference(block),
			Cell::MultiProofCell(mcell) => mcell.reference(block),
		}
	}

	pub fn data(&self) -> Vec<u8> {
		match self {
			Cell::SingleCell(cell) => cell.data().to_vec(),
			Cell::MultiProofCell(mcell) => mcell.data(),
		}
	}

	pub fn position(&self) -> Position {
		match self {
			Cell::SingleCell(cell) => cell.position,
			Cell::MultiProofCell(mcell) => mcell.position,
		}
	}

	pub fn proof(&self) -> [u8; 48] {
		match self {
			Cell::SingleCell(cell) => cell.proof(),
			Cell::MultiProofCell(mcell) => mcell.proof(),
		}
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		match self {
			Cell::MultiProofCell(mcell) => mcell.to_bytes(),
			Cell::SingleCell(cell) => cell.data().to_vec(),
		}
	}
}

impl From<SingleCell> for Cell {
	fn from(cell: SingleCell) -> Self {
		Cell::SingleCell(cell)
	}
}

impl From<MultiProofCell> for Cell {
	fn from(mcell: MultiProofCell) -> Self {
		Cell::MultiProofCell(mcell)
	}
}

impl TryFrom<Cell> for SingleCell {
	type Error = &'static str;

	fn try_from(value: Cell) -> Result<Self, Self::Error> {
		match value {
			Cell::SingleCell(cell) => Ok(cell),
			Cell::MultiProofCell(_) => Err("Expected SingleCell, found MultiProofCell"),
		}
	}
}

/// Merges cells data per row.
/// Cells are sorted before merge.
pub fn rows(dimensions: Dimensions, cells: &[&SingleCell]) -> Vec<(RowIndex, Vec<u8>)> {
	let mut sorted_cells = cells.to_vec();

	sorted_cells
		.sort_by(|a, b| (a.position.row, a.position.col).cmp(&(b.position.row, b.position.col)));

	let mut rows = BTreeMap::new();
	for cell in sorted_cells {
		rows.entry(RowIndex(cell.position.row))
			.or_insert_with(Vec::default)
			.extend(cell.data());
	}

	rows.retain(|_, row| row.len() == dimensions.row_byte_size());
	rows.into_iter().collect::<Vec<(_, _)>>()
}

/// Merges multiproof cells data per row.
/// Cells are sorted before merge.
pub fn mrows(dimensions: Dimensions, multiproof_cells: &[&MultiProofCell]) -> Vec<(RowIndex, Vec<u8>)> {
	let mut sorted_cells = multiproof_cells.to_vec();

	sorted_cells
		.sort_by(|a, b| (a.position.row, a.position.col).cmp(&(b.position.row, b.position.col)));

	let mut rows = BTreeMap::new();
	for cell in sorted_cells {
		rows.entry(RowIndex(cell.position.row))
			.or_insert_with(Vec::default)
			.extend(cell.data());
	}

	rows.retain(|_, row| row.len() == dimensions.row_byte_size());
	rows.into_iter().collect::<Vec<(_, _)>>()
}

impl From<SingleCell> for DataCell {
	fn from(cell: SingleCell) -> Self {
		DataCell {
			position: cell.position,
			data: cell.data(),
		}
	}
}

#[cfg(test)]
mod tests {
	use std::convert::TryInto;

	use crate::{
		data::SingleCell,
		data::{rows, GCellBlock, MultiProofCell},
		matrix::{Dimensions, Position},
	};

	use super::Cell;

	fn cell(position: Position, content: [u8; 80]) -> SingleCell {
		SingleCell { position, content }
	}

	fn position(row: u32, col: u16) -> Position {
		Position { row, col }
	}

	fn content(data: [u8; 32]) -> [u8; 80] {
		[&[0u8; 48], &data[..]].concat().try_into().unwrap()
	}

	#[test]
	fn rows_ok() {
		let dimensions = Dimensions::new(1, 2).unwrap();

		let cell_variants = vec![
			cell(position(1, 1), content([3; 32])).into(),
			cell(position(1, 0), content([2; 32])).into(),
			cell(position(0, 0), content([0; 32])).into(),
			cell(position(0, 1), content([1; 32])).into(),
		];

		let cells: Vec<&SingleCell> = cell_variants.iter().collect();
		let mut rows = rows(dimensions, &cells);
		rows.sort_by_key(|(key, _)| key.0);

		let expected = [
			[[0u8; 32], [1u8; 32]].concat(),
			[[2u8; 32], [3u8; 32]].concat(),
		];

		for i in 0..1 {
			let (row_index, row) = &rows[i];
			assert_eq!(row_index.0, i as u32);
			assert_eq!(*row, expected[i]);
		}
	}

	#[test]
	fn rows_incomplete() {
		let dimensions = Dimensions::new(1, 2).unwrap();

		let cell_variants = vec![
			cell(position(1, 1), content([3; 32])).into(),
			cell(position(0, 0), content([0; 32])).into(),
			cell(position(0, 1), content([1; 32])).into(),
		];

		let cells: Vec<&SingleCell> = cell_variants.iter().collect();
		let mut rows = rows(dimensions, &cells);
		rows.sort_by_key(|(key, _)| key.0);

		assert_eq!(rows.len(), 1);
		let (row_index, row) = &rows[0];
		assert_eq!(row_index.0, 0);
		assert_eq!(*row, [[0u8; 32], [1u8; 32]].concat());
	}

	#[test]
	fn mcell_to_from_bytes_roundtrip() {
		let position = Position { row: 10, col: 5 };
		let proof = [1u8; 48];
		let gcell_block = GCellBlock {
			start_x: 0,
			start_y: 0,
			end_x: 10,
			end_y: 10,
		};
		let scalars = vec![[1u64, 2, 3, 4], [5, 6, 7, 8]];

		let mcell = MultiProofCell {
			position,
			proof,
			gcell_block,
			scalars,
		};

		let bytes = mcell.to_bytes();
		let deserialized =
			MultiProofCell::from_bytes(position, &bytes).expect("Deserialization should succeed");

		assert_eq!(deserialized.position, mcell.position);
		assert_eq!(deserialized.proof, mcell.proof);
		assert_eq!(deserialized.gcell_block, mcell.gcell_block);
		assert_eq!(deserialized.scalars, mcell.scalars);
	}

	#[test]
	fn celltype_to_from_bytes_roundtrip() {
		let position = Position { row: 20, col: 7 };
		let proof = [9u8; 48];
		let gcell_block = GCellBlock {
			start_x: 2,
			start_y: 3,
			end_x: 6,
			end_y: 9,
		};
		let scalars = vec![[10u64, 11, 12, 13]];

		let mcell = MultiProofCell {
			position,
			proof,
			gcell_block,
			scalars,
		};

		let cell_type = Cell::from(mcell.clone());
		let bytes = cell_type.to_bytes();
		let reconstructed =
			MultiProofCell::from_bytes(position, &bytes).expect("Deserialization should succeed");

		assert_eq!(reconstructed.position, mcell.position);
		assert_eq!(reconstructed.proof, mcell.proof);
		assert_eq!(reconstructed.gcell_block, mcell.gcell_block);
		assert_eq!(reconstructed.scalars, mcell.scalars);
	}
}
