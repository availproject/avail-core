#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::arithmetic_side_effects)]

use avail_core::{constants::kate::DATA_CHUNK_SIZE, BlockLengthColumns, BlockLengthRows};
use core::{
    convert::TryInto,
    num::{NonZeroU32, TryFromIntError},
};
pub use dusk_plonk::{commitment_scheme::kzg10::PublicParameters, prelude::BlsScalar};
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
pub use poly_multiproof as pmp;

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

/// TODO
///  - Dedup this from `kate-recovery` once that library support `no-std`.
#[cfg(feature = "std")]
pub mod testnet {
    use super::*;
    use hex_literal::hex;
    use once_cell::sync::Lazy;
    use pmp::ark_bls12_381::Fr;
    use poly_multiproof::ark_ff::{BigInt, Fp, PrimeField};
    use poly_multiproof::ark_serialize::CanonicalDeserialize;
    use poly_multiproof::method1::M1NoPrecomp;
    use poly_multiproof::traits::MSMEngine;
    use poly_multiproof::Pairing;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    use std::{collections::HashMap, sync::Mutex};

    static SRS_DATA: Lazy<Mutex<HashMap<u32, PublicParameters>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));

    /// constructs public parameters for a given degree
    pub fn public_params(max_degree: BlockLengthColumns) -> PublicParameters {
        let max_degree: u32 = max_degree.into();
        let mut srs_data_locked = SRS_DATA.lock().unwrap();
        srs_data_locked
            .entry(max_degree)
            .or_insert_with(|| {
                let mut rng = ChaChaRng::seed_from_u64(42);
                let max_degree = usize::try_from(max_degree).unwrap();
                PublicParameters::setup(max_degree, &mut rng).unwrap()
            })
            .clone()
    }

    const SEC_LIMBS: [u64; 4] = [
        16526363067508752668,
        17870878028964021343,
        15693365399533249662,
        1020900941429372507,
    ];
    const G1_BYTES: [u8; 48] = hex!("a45f754a9e94cccbb2cbe9d7c441b8b527026ef05e2a3aff4aa4bb1c57df3767fb669cc4c7639bd37e683653bdc50b5a");
    const G2_BYTES: [u8; 96] = hex!("b845ac5e7b4ec8541d012660276772e001c1e0475e60971884481d43fcbd44de2a02e9862dbf9f536c211814f6cc5448100bcda5dc707854af8e3829750d1fb18b127286aaa4fc959e732e2128a8a315f2f8f419bf5774fe043af46fbbeb4b27");

    pub fn multiproof_params<E: Pairing, M: MSMEngine<E = E>>(
        max_degree: usize,
        max_pts: usize,
    ) -> M1NoPrecomp<E, M>
    where
        E::ScalarField: PrimeField + From<Fr>,
        E::G1: CanonicalDeserialize,
        E::G2: CanonicalDeserialize,
    {
        let x: <E as Pairing>::ScalarField =
            Fp(BigInt(SEC_LIMBS), core::marker::PhantomData).into();
        let g1: E::G1 = E::G1::deserialize_compressed(&G1_BYTES[..]).unwrap();
        let g2: E::G2 = E::G2::deserialize_compressed(&G2_BYTES[..]).unwrap();

        M1NoPrecomp::<E, M>::new_from_scalar(x, g1, g2, max_degree.saturating_add(1), max_pts)
    }

    #[cfg(test)]
    mod tests {
        use core::marker::PhantomData;

        use super::*;
        use dusk_bytes::Serializable;
        use dusk_plonk::{
            fft::{EvaluationDomain as PlonkED, Evaluations as PlonkEV},
            prelude::BlsScalar,
        };
        use pmp::ark_bls12_381::Bls12_381;
        use poly_multiproof::{
            ark_ff::{BigInt, Fp},
            ark_poly::{EvaluationDomain, GeneralEvaluationDomain},
            ark_serialize::CanonicalSerialize,
            msm::blst::BlstMSMEngine,
            traits::Committer,
        };
        use rand::thread_rng;

        use crate::testnet;
        #[test]
        fn test_consistent_testnet_params() {
            let x: Fr = Fp(BigInt(SEC_LIMBS), core::marker::PhantomData);
            let mut out = [0u8; 32];
            x.serialize_compressed(&mut out[..]).unwrap();
            const SEC_BYTES: [u8; 32] =
                hex!("7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a");
            assert_eq!(SEC_BYTES, out);

            let g1 = <Bls12_381 as Pairing>::G1::deserialize_compressed(&G1_BYTES[..]).unwrap();
            let g2 = <Bls12_381 as Pairing>::G2::deserialize_compressed(&G2_BYTES[..]).unwrap();

            let pmp = poly_multiproof::method1::M1NoPrecomp::<_, BlstMSMEngine>::new_from_scalar(
                x, g1, g2, 1024, 256,
            );

            let dp_evals = (0..30)
                .map(|_| BlsScalar::random(&mut thread_rng()))
                .collect::<Vec<_>>();

            let pmp_evals = dp_evals
                .iter()
                .map(|i| Fp(BigInt(i.0), PhantomData))
                .collect::<Vec<Fr>>();

            let dp_poly =
                PlonkEV::from_vec_and_domain(dp_evals, PlonkED::new(1024).unwrap()).interpolate();
            let pmp_ev = GeneralEvaluationDomain::<Fr>::new(1024).unwrap();
            let pmp_poly = pmp_ev.ifft(&pmp_evals);

            let pubs = testnet::public_params(BlockLengthColumns(1024));

            let dp_commit = pubs.commit_key().commit(&dp_poly).unwrap().0.to_bytes();
            let mut pmp_commit = [0u8; 48];
            pmp.commit(pmp_poly)
                .unwrap()
                .0
                .serialize_compressed(&mut pmp_commit[..])
                .unwrap();

            assert_eq!(dp_commit, pmp_commit);
        }
    }
}

// TODO: load pp for both dusk & arkworks from same file
// To be used for incentivised testnet
pub mod couscous {
    use super::*;
    use pmp::ark_bls12_381::{G1Projective as G1, G2Projective as G2};
    use pmp::ark_serialize::CanonicalDeserialize;
    use pmp::method1::M1NoPrecomp;
    use pmp::traits::MSMEngine;
    use pmp::Pairing;
    /// Constructs public parameters from pre-generated points for degree upto 1024
    pub fn public_params() -> PublicParameters {
        // We can also use the raw data to make deserilization faster at the cost of size of the data
        let pp_bytes = include_bytes!("pp_1024.data");
        PublicParameters::from_slice(pp_bytes).expect("Deserialization should work")
    }

    // Loads the pre-generated trusted g1 & g2 from the file
    fn load_trusted_g1_g2() -> (Vec<G1>, Vec<G2>) {
        // For degree 1024, we include 513 G2 points.
        // The rationale is that in multiproof constructions, we never need more than half the degree in G2 points.
        // Creating a multiproof grid with width equal to the original data grid doesn't make sense.
        let contents = include_str!("g1_g2_1024.txt");
        let mut lines = contents.lines();
        let g1_len: usize = lines.next().unwrap().parse().unwrap();
        let g2_len: usize = lines.next().unwrap().parse().unwrap();

        let g1_bytes: Vec<[u8; 48]> = lines
            .by_ref()
            .take(g1_len)
            .map(|line| hex::decode(line).unwrap().try_into().unwrap())
            .collect();

        let g2_bytes: Vec<[u8; 96]> = lines
            .take(g2_len)
            .map(|line| hex::decode(line).unwrap().try_into().unwrap())
            .collect();

        let g1: Vec<G1> = g1_bytes
            .iter()
            .map(|bytes| G1::deserialize_compressed(&bytes[..]).unwrap())
            .collect();

        let g2: Vec<G2> = g2_bytes
            .iter()
            .map(|bytes| G2::deserialize_compressed(&bytes[..]).unwrap())
            .collect();

        (g1, g2)
    }

    ///  Construct public parameters from pre-generated points for degree upto 1024
    pub fn multiproof_params<E: Pairing<G1 = G1, G2 = G2>, M: MSMEngine<E = E>>(
    ) -> M1NoPrecomp<E, M> {
        let (g1, g2) = load_trusted_g1_g2();
        <M1NoPrecomp<_, _>>::new_from_powers(&g1, &g2)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::pmp::msm::blst::BlstMSMEngine;
        use ark_bls12_381::{Bls12_381, Fr};
        use pmp::{
            ark_poly::{
                univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
                GeneralEvaluationDomain,
            },
            traits::KZGProof,
        };
        use poly_multiproof::{ark_bls12_381, traits::Committer};
        use rand::thread_rng;

        #[test]
        fn test_public_params() {
            let pmp = couscous::multiproof_params::<Bls12_381, BlstMSMEngine>();

            let points = DensePolynomial::<Fr>::rand(1024, &mut thread_rng()).coeffs;
            let pmp_ev = GeneralEvaluationDomain::<Fr>::new(1024).unwrap();
            let pmp_poly = pmp_ev.ifft(&points);
            let pmp_domain_pts = pmp_ev.elements().collect::<Vec<_>>();

            let pmp_commit = pmp.commit(&pmp_poly).unwrap();

            let proof = pmp
                .open(
                    pmp.compute_witness_polynomial(pmp_poly, pmp_domain_pts[1])
                        .unwrap(),
                )
                .unwrap();

            let verify = pmp
                .verify::<BlstMSMEngine>(&pmp_commit, pmp_domain_pts[1], points[1], &proof)
                .unwrap();

            assert!(verify);
        }
    }
}

pub mod metrics;

#[cfg(feature = "std")]
pub mod com;

pub mod gridgen;

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
