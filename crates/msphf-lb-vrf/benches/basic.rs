#![cfg(feature = "bench")]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use msphf_lb_vrf::VRF;
use msphf_lb_vrf::lbvrf::LBVRF;
use msphf_lb_vrf::param::Param;
use msphf_lb_vrf::poly::PolyArith;
use msphf_lb_vrf::poly256::*;
use rand::RngCore;
use std::time::Duration;

fn ot_lbvrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("one_time_lbvrf");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];

    group.bench_function(BenchmarkId::new("paramgen", "chaos"), |b| {
        b.iter(|| {
            rng.fill_bytes(&mut seed);
            LBVRF::paramgen(seed).expect("paramgen");
        });
    });

    let param: Param = LBVRF::paramgen(seed).expect("paramgen");
    group.bench_function(BenchmarkId::new("keygen", "chaos"), |b| {
        b.iter(|| {
            rng.fill_bytes(&mut seed);
            LBVRF::keygen(seed, param).expect("keygen");
        });
    });

    let (pk, sk) = LBVRF::keygen(seed, param).expect("keygen");
    let message = "this is a message that vrf signs";

    group.bench_function(BenchmarkId::new("prove", "chaos"), |b| {
        b.iter(|| {
            rng.fill_bytes(&mut seed);
            LBVRF::prove(message, param, pk, sk.clone(), seed).expect("prove");
        });
    });

    let proof = LBVRF::prove(message, param, pk, sk, seed).expect("prove");
    group.bench_function(BenchmarkId::new("verify", "chaos"), |b| {
        b.iter(|| {
            LBVRF::verify(message, param, pk, proof).expect("verify");
        });
    });

    group.finish();
}

fn trinary_poly(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly_ops");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    let mut rng = rand::thread_rng();

    group.bench_function(BenchmarkId::new("mul_trinary", "trinary"), |b| {
        b.iter(|| {
            let a = Poly256::uniform_random(&mut rng);
            let b = Poly256::rand_trinary(&mut rng);
            Poly256::mul_trinary(&a, &b);
        });
    });

    group.bench_function(BenchmarkId::new("mul_general", "trinary"), |b| {
        b.iter(|| {
            let a = Poly256::uniform_random(&mut rng);
            let b = Poly256::rand_trinary(&mut rng);
            Poly256::mul(&a, &b);
        });
    });

    group.finish();
}

criterion_group!(benches, ot_lbvrf, trinary_poly);
criterion_main!(benches);
