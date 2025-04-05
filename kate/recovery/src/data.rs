use codec::{Decode, Encode};
use core::convert::TryInto;
use derive_more::Constructor;
use serde::{Deserialize, Serialize};
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};
use std::convert::TryFrom;

use crate::matrix::{Dimensions, Position, RowIndex};

#[cfg(target_arch = "wasm32")]
extern crate alloc;
#[cfg(target_arch = "wasm32")]
use alloc::string::String;

/// Position and data of a cell in extended matrix
#[derive(Default, Debug, Clone, Constructor)]
pub struct DataCell {
    /// Cell's position
    pub position: Position,
    /// Cell's data
    pub data: [u8; 32],
}

/// Position and content of a cell in extended matrix
#[derive(Debug, Clone, Constructor)]
pub struct Cell {
    /// Cell's position
    pub position: Position,
    /// Cell's data
    pub content: [u8; 80],
}

impl Cell {
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
pub struct MCell {
    pub position: Position,
    pub content: Vec<[u64; 4]>,
    pub proof: [u8; 48],
    pub gcell_block: GCellBlock,
}

#[derive(Encode, Decode, Debug, Clone, Serialize, Deserialize)]
pub struct GCellBlock {
    pub start_x: u32,
    pub start_y: u32,
    pub end_x: u32,
    pub end_y: u32,
}

impl GCellBlock {
    pub const GCELL_BLOCK_SIZE: usize = std::mem::size_of::<GCellBlock>();

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::GCELL_BLOCK_SIZE);
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

impl MCell {
    #[cfg(any(target_arch = "wasm32", feature = "std"))]
    pub fn reference(&self, block: u32) -> String {
        self.position.reference(block)
    }

    pub fn data(&self) -> Vec<u8> {
        let mut content = Vec::with_capacity(self.content.len() * 32);
        for scalar in &self.content {
            for &limb in scalar {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&limb.to_be_bytes()); 
                content.extend_from_slice(&buf);
            }
        }
    
        content
    }

    pub fn proof(&self) -> [u8; 48] {
        self.proof
    }

    pub fn gcell_block(&self) -> &GCellBlock {
        &self.gcell_block
    }
}

#[derive(Debug, Clone)]
pub enum CellVariant {
    Cell(Cell),
    MCell(MCell),
}

impl CellVariant {
    #[cfg(any(target_arch = "wasm32", feature = "std"))]
    pub fn reference(&self, block: u32) -> String {
        match self {
            CellVariant::Cell(cell) => cell.reference(block),
            CellVariant::MCell(mcell) => mcell.reference(block),
        }
    }

    pub fn data(&self) -> Vec<u8> {
        match self {
            CellVariant::Cell(cell) => cell.data().to_vec(),
            CellVariant::MCell(mcell) => mcell.data(),
        }
    }

    pub fn position(&self) -> Position {
        match self {
            CellVariant::Cell(cell) => cell.position,
            CellVariant::MCell(mcell) => mcell.position,
        }
    }

    pub fn proof(&self) -> [u8; 48] {
        match self {
            CellVariant::Cell(cell) => cell.proof(),
            CellVariant::MCell(mcell) => mcell.proof(),
        }
    }

    pub fn gcell_block(&self) -> Option<&GCellBlock> {
        match self {
            CellVariant::Cell(_) => None,
            CellVariant::MCell(mcell) => Some(mcell.gcell_block()),
        }
    }
}

impl From<Cell> for CellVariant {
    fn from(cell: Cell) -> Self {
        CellVariant::Cell(cell)
    }
}

impl From<MCell> for CellVariant {
    fn from(mcell: MCell) -> Self {
        CellVariant::MCell(mcell)
    }
}

impl TryFrom<CellVariant> for Cell {
    type Error = &'static str;

    fn try_from(value: CellVariant) -> Result<Self, Self::Error> {
        match value {
            CellVariant::Cell(cell) => Ok(cell),
            CellVariant::MCell(_) => Err("Expected Cell, found MCell"),
        }
    }
}

/// Merges cells data per row.
/// Cells are sorted before merge.
pub fn rows(dimensions: Dimensions, cells: &[&CellVariant]) -> Vec<(RowIndex, Vec<u8>)> {
    let mut sorted_cells = cells.to_vec();

    sorted_cells.sort_by(|a, b| {
        (a.position().row, a.position().col).cmp(&(b.position().row, b.position().col))
    });

    let mut rows = BTreeMap::new();
    for cell in sorted_cells {
        rows.entry(RowIndex(cell.position().row))
            .or_insert_with(Vec::default)
            .extend(cell.data());
    }

    rows.retain(|_, row| row.len() == dimensions.row_byte_size());
    rows.into_iter().collect::<Vec<(_, _)>>()
}

impl From<Cell> for DataCell {
    fn from(cell: Cell) -> Self {
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
        data::rows,
        data::Cell,
        matrix::{Dimensions, Position},
    };

    use super::CellVariant;

    fn cell(position: Position, content: [u8; 80]) -> Cell {
        Cell { position, content }
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

        let cells: Vec<&CellVariant> = cell_variants.iter().collect();
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

        let cells: Vec<&CellVariant> = cell_variants.iter().collect();
        let mut rows = rows(dimensions, &cells);
        rows.sort_by_key(|(key, _)| key.0);

        assert_eq!(rows.len(), 1);
        let (row_index, row) = &rows[0];
        assert_eq!(row_index.0, 0);
        assert_eq!(*row, [[0u8; 32], [1u8; 32]].concat());
    }
}
