use core::convert::TryInto;
use derive_more::Constructor;
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};

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

/// Position and content of a multiproof cell in extended matrix
#[derive(Debug, Clone, Constructor)]
pub struct MCell {
    /// Position of a multiproof cell
    pub position: Position,
    /// Concatenated cell data
    pub content: Vec<u8>,
}

impl MCell {
    #[cfg(any(target_arch = "wasm32", feature = "std"))]
    pub fn reference(&self, block: u32) -> String {
        self.position.reference(block)
    }

    pub fn data(&self) -> Vec<u8> {
        self.content[48..].to_vec()
    }

    pub fn proof(&self) -> [u8; 48] {
        self.content[..48].try_into().expect("content is 80 bytes")
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
}

/// Merges cells data per row.
/// Cells are sorted before merge.
pub fn rows(dimensions: Dimensions, cells: &[&CellVariant]) -> Vec<(RowIndex, Vec<u8>)> {
    let mut sorted_cells = cells.to_vec();

    sorted_cells
        .sort_by(|a, b| (a.position().row, a.position().col).cmp(&(b.position().row, b.position().col)));

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

        let cell_variants= vec![
            CellVariant::Cell(cell(position(1, 1), content([3; 32]))),
            CellVariant::Cell(cell(position(1, 0), content([2; 32]))),
            CellVariant::Cell(cell(position(0, 0), content([0; 32]))),
            CellVariant::Cell(cell(position(0, 1), content([1; 32]))),
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
            CellVariant::Cell(cell(position(1, 1), content([3; 32]))),
            CellVariant::Cell(cell(position(0, 0), content([0; 32]))),
            CellVariant::Cell(cell(position(0, 1), content([1; 32]))),
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
