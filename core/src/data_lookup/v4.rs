use codec::{Decode, Encode, Input};
use core::convert::TryFrom;
use scale_info::{Type, TypeInfo};
use sp_std::vec;
use sp_std::{ops::Range, vec::Vec};
use thiserror_no_std::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use sp_debug_derive::RuntimeDebug;

use crate::{ensure, v4_compact, AppId, V3DataLookup::DataLookup as V3DataLookup};

use v4_compact::CompactDataLookup;

pub type DataLookupRange = Range<u32>;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	#[error("Input data is not sorted by AppId")]
	DataNotSorted,
	#[error("Data is empty on AppId {0}")]
	DataEmptyOn(AppId),
	#[error("Offset overflows")]
	OffsetOverflows,
	#[error("Lookup has no transactions")]
	EmptyTransactions,
}

#[derive(PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
	feature = "serde",
	serde(try_from = "CompactDataLookup", into = "CompactDataLookup")
)]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
pub struct DataLookup {
	pub(crate) index: Vec<(AppId, DataLookupRange)>,
	pub(crate) rows_per_tx: Vec<u16>,
}

impl DataLookup {
	pub fn len(&self) -> u32 {
		self.index.last().map_or(0, |(_id, range)| range.end)
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	pub fn is_error(&self) -> bool {
		self.is_empty() && !self.index.is_empty()
	}

	pub fn range_of(&self, app_id: AppId) -> Option<DataLookupRange> {
		self.index
			.iter()
			.find(|(id, _)| *id == app_id)
			.map(|(_, range)| range)
			.cloned()
	}

	pub fn projected_range_of(&self, app_id: AppId, chunk_size: u32) -> Option<DataLookupRange> {
		self.range_of(app_id).and_then(|range| {
			let start = range.start.checked_mul(chunk_size)?;
			let end = range.end.checked_mul(chunk_size)?;
			Some(start..end)
		})
	}

	/// It projects `self.index` into _chunked_ indexes.
	/// # Errors
	/// It raises `Error::OffsetOverflows` up if any index multiplied by `chunk_size` overflows.
	pub fn projected_ranges(&self, chunk_size: u32) -> Result<Vec<(AppId, Range<u32>)>, Error> {
		self.index
			.iter()
			.map(|(id, range)| {
				let start = range
					.start
					.checked_mul(chunk_size)
					.ok_or(Error::OffsetOverflows)?;
				let end = range
					.end
					.checked_mul(chunk_size)
					.ok_or(Error::OffsetOverflows)?;
				Ok((*id, start..end))
			})
			.collect()
	}

	/// Returns the tx row indices associated with a given app_id.
	pub fn app_txs(&self, app_id: AppId) -> Option<Vec<Vec<u32>>> {
		let range = self.range_of(app_id)?;
		let start = range.start as usize;
		let end = range.end as usize;

		let mut tx_rows = Vec::new();
		let mut tx_start = start;
		let mut current_index = 0;

		for &rows in &self.rows_per_tx {
			let rows = rows as usize;
			if current_index + rows > start {
				let tx_row_indices = (tx_start..tx_start + rows.min(end - tx_start))
					.map(|i| i as u32)
					.collect();
				tx_rows.push(tx_row_indices);
				tx_start += rows;
			}
			current_index += rows;
			if tx_start >= end {
				break;
			}
		}

		Some(tx_rows)
	}

	/// Returns the transaction row indices for all app_ids in the lookup.
	pub fn transactions(&self) -> Option<Vec<(AppId, Vec<Vec<u32>>)>> {
		let mut result = Vec::new();

		for (app_id, _) in &self.index {
			if let Some(tx_rows) = self.app_txs(*app_id) {
				result.push((*app_id, tx_rows));
			}
		}

		if result.is_empty() {
			None
		} else {
			Some(result)
		}
	}

	pub fn from_id_and_len_iter<I, A, L>(iter: I) -> Result<Self, Error>
	where
		I: Iterator<Item = (A, L)>,
		u32: From<A>,
		u32: TryFrom<L>,
	{
		let mut offset: u32 = 0;
		let mut last_id: Option<AppId> = None;
		let mut index = Vec::new();
		let mut rows_per_tx = Vec::new();
		let mut current_rows_per_tx = Vec::new(); // Temporary storage for per-app transactions

		for (id, len) in iter {
			let id = AppId(id.into());
			let len = u32::try_from(len).map_err(|_| Error::OffsetOverflows)?;
			ensure!(len > 0, Error::DataEmptyOn(id));

			// Enforce sorted order: App IDs must be non-decreasing
			if let Some(prev_id) = last_id {
				ensure!(id.0 >= prev_id.0, Error::DataNotSorted);
			}

			if Some(id) != last_id {
				// If switching to a new app_id, store previous index and rows_per_tx data
				if let Some(prev_id) = last_id {
					let range_start =
						offset - current_rows_per_tx.iter().map(|&r| r as u32).sum::<u32>();
					index.push((prev_id, range_start..offset));
					rows_per_tx.extend(current_rows_per_tx.iter());
				}
				last_id = Some(id);
				current_rows_per_tx.clear();
			}

			offset = offset.checked_add(len).ok_or(Error::OffsetOverflows)?;
			current_rows_per_tx.push(len as u16);
		}

		// Add the last app_id's data
		if let Some(last_id) = last_id {
			let range_start = offset - current_rows_per_tx.iter().map(|&r| r as u32).sum::<u32>();
			index.push((last_id, range_start..offset));
			rows_per_tx.extend(current_rows_per_tx.iter());
		}

		Ok(Self { index, rows_per_tx })
	}

	/// This function is used a block contains no data submissions.
	pub fn new_empty() -> Self {
		Self {
			index: Vec::new(),
			rows_per_tx: Vec::new(),
		}
	}

	/// This function is only used when something has gone wrong during header extension building
	pub fn new_error() -> Self {
		Self {
			index: vec![(AppId(0), 0..0)],
			rows_per_tx: Vec::new(),
		}
	}
}

impl TryFrom<CompactDataLookup> for DataLookup {
	type Error = Error;

	fn try_from(compacted: CompactDataLookup) -> Result<Self, Self::Error> {
		if compacted.is_error() {
			return Ok(DataLookup::new_error());
		}

		let mut offset = 0;
		let mut prev_id = AppId(0);
		let mut index = Vec::with_capacity(
			compacted
				.index
				.len()
				.checked_add(1)
				.ok_or(Error::OffsetOverflows)?,
		);

		for c_item in compacted.index {
			index.push((prev_id, offset..c_item.start));
			prev_id = c_item.app_id;
			offset = c_item.start;
		}

		let last_range = offset..compacted.size;
		if !last_range.is_empty() {
			index.push((prev_id, last_range));
		}

		let lookup = DataLookup {
			index,
			rows_per_tx: compacted.rows_per_tx,
		};

		ensure!(lookup.len() == compacted.size, Error::DataNotSorted);

		Ok(lookup)
	}
}

impl From<V3DataLookup> for DataLookup {
	/// Converts from a V3DataLookup to DataLookup.
	fn from(v3_lookup: V3DataLookup) -> Self {
		let index = v3_lookup.index;
		let rows_per_tx = Vec::new();

		DataLookup { index, rows_per_tx }
	}
}

impl From<&V3DataLookup> for DataLookup {
	fn from(v3: &V3DataLookup) -> Self {
		// Similar logic but working with a reference
		let rows_per_tx = v3
			.index
			.iter()
			.map(|(_, range)| (range.end - range.start) as u16)
			.collect();

		DataLookup {
			index: v3.index.clone(),
			rows_per_tx,
		}
	}
}

// Encoding
// ==================================

impl Encode for DataLookup {
	/// Encodes as a `compact::DataLookup`.
	fn encode(&self) -> Vec<u8> {
		let compacted: CompactDataLookup = CompactDataLookup::from_data_lookup(self);
		compacted.encode()
	}
}

impl Decode for DataLookup {
	/// Decodes from a `compact::DataLookup`.
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		let compacted = CompactDataLookup::decode(input)?;
		DataLookup::try_from(compacted).map_err(|_| codec::Error::from("Invalid `DataLookup`"))
	}
}

impl TypeInfo for DataLookup {
	type Identity = Self;

	fn type_info() -> Type {
		CompactDataLookup::type_info()
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use test_case::test_case;

	#[test_case( vec![(0, 15), (1, 20), (2, 150)] => Ok(vec![(0,0..15),(1, 15..35), (2, 35..185)]); "Valid case")]
	#[test_case( vec![(0, usize::MAX)] => Err(Error::OffsetOverflows); "Offset overflows at zero")]
	#[test_case( vec![(0, (u32::MAX -1) as usize), (1, 2)] => Err(Error::OffsetOverflows); "Offset overflows at non zero")]
	#[test_case( vec![(1, 10), (0, 2)] => Err(Error::DataNotSorted); "Unsorted data")]
	#[test_case( vec![] => Ok(vec![]); "Empty data")]
	fn from_id_and_len(
		id_len_data: Vec<(u32, usize)>,
	) -> Result<Vec<(u32, DataLookupRange)>, Error> {
		let iter = id_len_data.into_iter().map(|(id, len)| (AppId(id), len));

		DataLookup::from_id_and_len_iter(iter).map(|lookup| {
			lookup
				.index
				.iter()
				.map(|(id, range)| (id.0, range.clone()))
				.collect::<Vec<_>>()
		})
	}

	#[test_case(
		vec![(0, 15),(1, 20),(2, 150)]
		=> CompactDataLookup::new(185, vec![(1u32, 15u32).into(),(2u32,35u32).into()],vec![15, 20, 150]).encode();
		"Valid case"
	)]
	#[test_case(
		vec![(0, 100)]
		=> CompactDataLookup::new(100, vec![], vec![100]).encode();
		"Only Zero AppId"
	)]
	#[test_case( vec![] => CompactDataLookup::new(0, vec![], vec![]).encode(); "Empty")]
	fn check_compressed_encode(id_lens: Vec<(u32, usize)>) -> Vec<u8> {
		let lookup = DataLookup::from_id_and_len_iter(id_lens.into_iter()).unwrap();
		lookup.encode()
	}

	#[test_case( vec![(0, 15), (1, 20), (2, 150)] ; "Valid case")]
	#[test_case( vec![(0, 15)] ; "Only Zero AppId")]
	#[test_case( vec![] ; "Empty")]
	fn compressed_conversions(id_lens: Vec<(u32, usize)>) {
		let lookup = DataLookup::from_id_and_len_iter(id_lens.into_iter()).unwrap();

		let compact_lookup = CompactDataLookup::from_data_lookup(&lookup);
		let expanded_lookup = DataLookup::try_from(compact_lookup.clone()).unwrap();

		assert_eq!(
			lookup, expanded_lookup,
			"Lookup: {lookup:?} -> Compacted: {compact_lookup:?} -> Expanded: {expanded_lookup:?}"
		);
	}

	#[test_case( vec![(0, 15), (1, 20), (2, 150)] ; "Valid case")]
	#[test_case( vec![(0, 15)] ; "Only Zero AppId")]
	#[test_case( vec![] ; "Empty")]
	fn serialization_compatibility(id_lens: Vec<(u32, usize)>) {
		let lookup = DataLookup::from_id_and_len_iter(id_lens.into_iter()).unwrap();
		let lookup_json = serde_json::to_string(&lookup).unwrap();
		let compressed_from_json = serde_json::from_str::<CompactDataLookup>(&lookup_json).unwrap();
		let expanded_lookup = DataLookup::try_from(compressed_from_json.clone()).unwrap();

		assert_eq!(lookup, expanded_lookup);
	}

	#[test]
	fn test_from_id_and_len_iter() {
		let input: Vec<(u32, u32)> = vec![(1, 15), (1, 20), (2, 150)];
		let data_lookup = DataLookup::from_id_and_len_iter(input.into_iter()).unwrap();

		assert_eq!(data_lookup.rows_per_tx, vec![15, 20, 150]); // Ensuring correct row counts
		assert_eq!(
			data_lookup.index,
			vec![(AppId(1), 0..35), (AppId(2), 35..185)]
		); // Ensuring correct indexing
	}

	#[test]
	fn test_app_txs() {
		let app_id_len = vec![(AppId(3), 2), (AppId(3), 2), (AppId(4), 3)];
		let data_lookup = DataLookup::from_id_and_len_iter(app_id_len.into_iter()).unwrap();

		let compact_lookup = CompactDataLookup::from_data_lookup(&data_lookup);
		println!("compact_lookup: {:#?}", compact_lookup);
		let rec_compact_lookup = DataLookup::try_from(compact_lookup).unwrap();
		println!("rec_compact_lookup: {:#?}", rec_compact_lookup);

		// Test for AppId 3
		let app_id_3_txs = data_lookup.app_txs(AppId(3)).unwrap();
		assert_eq!(app_id_3_txs, vec![vec![0, 1], vec![2, 3]]);

		// Test for AppId 4
		let app_id_4_txs = data_lookup.app_txs(AppId(4)).unwrap();
		assert_eq!(app_id_4_txs, vec![vec![4, 5, 6]]);

		// Test for non-existent AppId
		let app_id_5_txs = data_lookup.app_txs(AppId(5));
		assert!(app_id_5_txs.is_none());

		// Test transactions
		let txs = data_lookup.transactions().unwrap();
		assert_eq!(
			txs,
			vec![
				(AppId(3), vec![vec![0, 1], vec![2, 3]]),
				(AppId(4), vec![vec![4, 5, 6]])
			]
		);
	}
}
