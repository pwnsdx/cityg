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
            match LBVRF::paramgen(seed) {
                Ok(_) => {}
                Err(_) => unreachable!(),
            }
        });
    });

    let param: Param = match LBVRF::paramgen(seed) {
        Ok(p) => p,
        Err(_) => unreachable!(),
    };
    group.bench_function(BenchmarkId::new("keygen", "chaos"), |b| {
        b.iter(|| {
            rng.fill_bytes(&mut seed);
            match LBVRF::keygen(seed, param) {
                Ok(_) => {}
                Err(_) => unreachable!(),
            }
        });
    });

    let (pk, sk) = match LBVRF::keygen(seed, param) {
        Ok(keys) => keys,
        Err(_) => unreachable!(),
    };
    let message = "this is a message that vrf signs";

    group.bench_function(BenchmarkId::new("prove", "chaos"), |b| {
        b.iter(|| {
            rng.fill_bytes(&mut seed);
            match LBVRF::prove(message, param, pk, sk.clone(), seed) {
                Ok(_) => {}
                Err(_) => unreachable!(),
            }
        });
    });

    let proof = match LBVRF::prove(message, param, pk, sk, seed) {
        Ok(p) => p,
        Err(_) => unreachable!(),
    };
    group.bench_function(BenchmarkId::new("verify", "chaos"), |b| {
        b.iter(|| match LBVRF::verify(message, param, pk, proof) {
            Ok(_) => {}
            Err(_) => unreachable!(),
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
