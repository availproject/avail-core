use avail_core::{AppExtrinsic, AppId, BlockLengthColumns, BlockLengthRows};
use core::num::NonZeroU16;
use hex_literal::hex;
use kate::{
    couscous::multiproof_params,
    gridgen::EvaluationGrid,
    pmp::{merlin::Transcript, traits::PolyMultiProofNoPrecomp},
    Seed,
};
use kate_recovery::matrix::Dimensions;
use poly_multiproof::ark_bls12_381::Bls12_381;
use poly_multiproof::method1::M1NoPrecomp;
use poly_multiproof::msm::blst::BlstMSMEngine;
use poly_multiproof::traits::AsBytes;
use thiserror_no_std::Error;

#[derive(Error, Debug)]
enum AppError {
    Kate(#[from] kate::com::Error),
    MultiProof(#[from] poly_multiproof::Error),
}

fn main() -> Result<(), AppError> {
    let verified = multiproof_verification()?;
    println!("Multiproof verfication is {verified}");

    Ok(())
}

fn multiproof_verification() -> Result<bool, AppError> {
    type E = Bls12_381;
    type M = BlstMSMEngine;
    let target_dims = Dimensions::new_from(16, 64).unwrap();
    let pp: M1NoPrecomp<E, M> = multiproof_params();
    let points = kate::gridgen::domain_points(256)?;
    let exts_data = vec![
        hex!("CAFEBABE00000000000000000000000000000000000000").to_vec(),
        hex!("DEADBEEF1111111111111111111111111111111111").to_vec(),
        hex!("1234567899999999999999999999999999999999").to_vec(),
    ];
    let (proof, evals, commitments, dims) = {
        let exts = exts_data
            .into_iter()
            .enumerate()
            .map(|(i, data)| AppExtrinsic::new(AppId(i as u32), data))
            .collect::<Vec<_>>();
        let seed = Seed::default();
        let grid = EvaluationGrid::from_extrinsics(exts, 4, 256, 256, seed)?
            .extend_columns(unsafe { NonZeroU16::new_unchecked(2) })?;

        // Setup, serializing as bytes
        let polys = grid.make_polynomial_grid()?;

        let commitments = polys
            .commitments(&pp)
            .unwrap()
            .iter()
            .flat_map(|c| c.to_bytes().unwrap())
            .collect::<Vec<_>>();

        let multiproof = polys
            .multiproof(
                &pp,
                &kate::com::Cell::new(BlockLengthRows(0), BlockLengthColumns(0)),
                &grid,
                target_dims,
            )
            .unwrap();

        let proof_bytes = multiproof.proof.to_bytes()?;
        let evals_bytes = multiproof
            .evals
            .iter()
            .flat_map(|row| row.iter().flat_map(|e| e.to_bytes().unwrap()))
            .collect::<Vec<_>>();
        (proof_bytes, evals_bytes, commitments, grid.dims())
    };

    let mp_block = kate::gridgen::multiproof_block(0, 0, dims, target_dims).unwrap();
    let commits = commitments
        .chunks_exact(48)
        .skip(mp_block.start_y)
        .take(mp_block.end_y - mp_block.start_y)
        .map(|c| kate::pmp::Commitment::from_bytes(c.try_into().unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let block_commits = &commits[mp_block.start_x..mp_block.end_x];
    let evals_flat = evals
        .chunks_exact(32)
        .map(|e| kate::ArkScalar::from_bytes(e.try_into().unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let evals_grid = evals_flat
        .chunks_exact(mp_block.end_x - mp_block.start_x)
        .collect::<Vec<_>>();

    let proof = kate::pmp::method1::Proof::from_bytes(&proof)?;

    let verified = pp.verify(
        &mut Transcript::new(b"avail-mp"),
        block_commits,
        &points[mp_block.start_x..mp_block.end_x],
        &evals_grid,
        &proof,
    )?;

    Ok(verified)
}
