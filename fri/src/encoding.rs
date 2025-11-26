use crate::error::FriBiniusError;
use binius_field::{ExtensionField, PackedField};
use binius_math::FieldBuffer;
use binius_verifier::config::B1;
use core::marker::PhantomData;

const BYTES_PER_ELEMENT: usize = 16; // 128 bits
const BITS_PER_ELEMENT: usize = 128;

pub struct BytesEncoder<P> {
	log_scalar_bit_width: usize,
	_p: PhantomData<P>,
}

pub struct PackedMLE<P>
where
	P: PackedField + ExtensionField<B1>,
	P::Scalar: From<u128> + ExtensionField<B1>,
{
	pub packed_mle: FieldBuffer<P>,
	pub packed_values: Vec<P::Scalar>,
	pub total_n_vars: usize,
}

impl<P> BytesEncoder<P>
where
	P: PackedField + ExtensionField<B1>,
	P::Scalar: From<u128> + ExtensionField<B1>,
{
	pub fn new() -> Self {
		Self {
			log_scalar_bit_width: <P::Scalar as ExtensionField<B1>>::LOG_DEGREE,
			_p: PhantomData,
		}
	}

	pub fn bytes_to_packed_mle(&self, data: &[u8]) -> Result<PackedMLE<P>, FriBiniusError> {
		if data.is_empty() {
			return Err(FriBiniusError::InvalidInput("input data must be non-empty"));
		}

		// Number of 128-bit field elements needed
		let num_elements = (data.len() * 8).div_ceil(BITS_PER_ELEMENT);
		let padded_size = num_elements.next_power_of_two();

		let big_field_n_vars = padded_size.ilog2() as usize;
		log::debug!("N vars (big field): {big_field_n_vars}");

		let packed_size = 1 << big_field_n_vars;
		log::debug!("Packed size: {packed_size}");

		#[cfg(feature = "parallel")]
		let mut packed_values: Vec<P::Scalar> = {
			use rayon::prelude::*;
			data.par_chunks(BYTES_PER_ELEMENT)
				.map(|chunk| {
					let mut bytes_array = [0u8; BYTES_PER_ELEMENT];
					bytes_array[..chunk.len()].copy_from_slice(chunk);
					P::Scalar::from(u128::from_le_bytes(bytes_array))
				})
				.collect()
		};

		#[cfg(not(feature = "parallel"))]
		let mut packed_values: Vec<P::Scalar> = {
			let mut values = Vec::with_capacity(num_elements);
			for chunk in data.chunks(BYTES_PER_ELEMENT) {
				let mut bytes_array = [0u8; BYTES_PER_ELEMENT];
				bytes_array[..chunk.len()].copy_from_slice(chunk);
				let scalar = P::Scalar::from(u128::from_le_bytes(bytes_array));
				values.push(scalar);
			}
			values
		};

		log::debug!("Packed values before padding: {}", packed_values.len());
		packed_values.resize(packed_size, P::Scalar::zero());
		log::debug!("Packed values after padding: {}", packed_values.len());

		let packed_mle = FieldBuffer::<P>::from_values(&packed_values)
			.map_err(|e| FriBiniusError::Encoding(e.to_string()))?;

		let big_field_n_vars = packed_mle.log_len();
		let total_n_vars = big_field_n_vars + self.log_scalar_bit_width;

		Ok(PackedMLE::<P> {
			packed_mle,
			packed_values,
			total_n_vars,
		})
	}
}

impl<P> Default for BytesEncoder<P>
where
	P: PackedField + ExtensionField<B1>,
	P::Scalar: From<u128> + ExtensionField<B1>,
{
	fn default() -> Self {
		Self::new()
	}
}
