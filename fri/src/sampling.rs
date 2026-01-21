use crate::error::FriBiniusError;
use binius_field::{Field, PackedField};
use binius_verifier::config::B128;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Extremely naive Reed–Solomon erasure reconstruction for testing only.
pub fn reconstruct_codeword_naive(
	corrupted_codeword: &mut [B128],
	corrupted_indices: &[usize],
) -> Result<(), FriBiniusError> {
	let n = corrupted_codeword.len();
	if corrupted_indices.is_empty() || n == 0 {
		return Ok(());
	}

	let domain: Vec<B128> = (0..n).map(|i| B128::from(i as u128)).collect();

	let known: Vec<(B128, B128)> = (0..n)
		.filter(|i| !corrupted_indices.contains(i))
		.map(|i| (domain[i], corrupted_codeword[i]))
		.collect();

	let k = known.len();
	if k == 0 {
		return Err(FriBiniusError::Reconstruction(
			"no known points available".into(),
		));
	}

	#[cfg(feature = "parallel")]
	let reconstructed: Vec<(usize, B128)> = corrupted_indices
		.par_iter()
		.map(|&missing| {
			log::debug!("Reconstructing index {missing}");
			let x_e = domain[missing];
			let mut value = B128::zero();

			for j in 0..k {
				let (x_j, y_j) = known[j];
				let mut l_j = B128::ONE;
				for (m, _) in known.iter().enumerate().take(k) {
					if m == j {
						continue;
					}
					let (x_m, _) = known[m];
					l_j = l_j * (x_e - x_m) * (x_j - x_m).invert().unwrap();
				}
				value += y_j * l_j;
			}

			(missing, value)
		})
		.collect();

	#[cfg(feature = "parallel")]
	{
		for (i, v) in reconstructed {
			corrupted_codeword[i] = v;
		}
		Ok(())
	}

	#[cfg(not(feature = "parallel"))]
	{
		for &missing in corrupted_indices {
			log::debug!("Reconstructing index {missing}");
			let x_e = domain[missing];
			let mut value = B128::zero();

			for j in 0..k {
				let (x_j, y_j) = known[j];
				let mut l_j = B128::ONE;
				for m in 0..k {
					if m == j {
						continue;
					}
					let (x_m, _) = known[m];
					l_j = l_j * (x_e - x_m) * (x_j - x_m).invert().unwrap();
				}
				value += y_j * l_j;
			}

			corrupted_codeword[missing] = value;
		}

		Ok(())
	}
}
