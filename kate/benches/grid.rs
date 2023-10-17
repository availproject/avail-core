use std::{num::NonZeroU16, time::Duration};

use avail_core::{AppExtrinsic, BlockLengthColumns};
use criterion::*;
use kate::{
	com::Cell,
	gridgen::{domain_points, EvaluationGrid},
};
use poly_multiproof::traits::KZGProof;
use rand::{thread_rng, RngCore, SeedableRng};

fn grids(c: &mut Criterion) {
	let mut data = vec![0u8; 65536 * 64 * 31];
    thread_rng().fill_bytes(&mut data);
	let pmp = poly_multiproof::m1_blst::M1NoPrecomp::new(65536, 256, &mut thread_rng());
	for (w, h) in vec![(256, 256), (1024, 1024), (65536, 64)] {
		let mut g = c.benchmark_group(format!("W{}_H{}", w, h));
        g.measurement_time(Duration::from_secs(10));
        g.sample_size(10);
		let ext = AppExtrinsic {
			app_id: avail_core::AppId(1),
			data: data[..(w * h-1) * 31].to_vec(),
		};
		let eval_grid = EvaluationGrid::from_extrinsics(vec![ext], 4, w, h, [42u8; 32]).unwrap();
		assert_eq!(eval_grid.dims().width(), w);
		assert_eq!(eval_grid.dims().height(), h);

		g.bench_function("extend_columns", |b| {
			b.iter(|| {
				eval_grid
					.extend_columns(NonZeroU16::new(2).unwrap())
					.unwrap()
			})
		}).measurement_time(Duration::from_secs(10));

		let extended = eval_grid
			.extend_columns(NonZeroU16::new(2).unwrap())
			.unwrap();
		g.bench_function("make_polys", |b| {
			b.iter(|| extended.make_polynomial_grid().unwrap())
		}).measurement_time(Duration::from_secs(10));

		let base_polys = eval_grid.make_polynomial_grid().unwrap();
		g.bench_function("commitments", |b| {
			b.iter(|| base_polys.extended_commitments(&pmp, 2).unwrap())
		}).measurement_time(Duration::from_secs(10));
		let polys = extended.make_polynomial_grid().unwrap();
		g.bench_function("open", |b| {
			b.iter(|| {
				polys
					.proof(
						&pmp,
						&Cell {
							row: avail_core::BlockLengthRows(0),
							col: BlockLengthColumns(0),
						},
					)
					.unwrap()
			})
		}).measurement_time(Duration::from_secs(10));
		let proof = polys
			.proof(
				&pmp,
				&Cell {
					row: avail_core::BlockLengthRows(0),
					col: BlockLengthColumns(0),
				},
			)
			.unwrap();
		let pts = domain_points(w).unwrap();
		let commit = polys.commitment(&pmp, 0).unwrap();
		g.bench_function("verify", |b| {
			b.iter(|| pmp.verify(&commit, pts[0], eval_grid.row(0).unwrap()[0], &proof))
		}).measurement_time(Duration::from_secs(10));
	}
}

criterion_group!(benches, grids);
criterion_main!(benches);
