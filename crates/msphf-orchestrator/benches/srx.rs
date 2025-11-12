#[cfg(feature = "bench-fixtures")]
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "bench-fixtures")]
use ciborium::value::Value;
#[cfg(feature = "bench-fixtures")]
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
#[cfg(feature = "bench-fixtures")]
use msphf_orchestrator::{
    AcceptInstant, SrxBenchHarness,
    fixtures::{header_ready_with_pop, sample_parts_params_joiner, sample_pop_keys},
};

#[cfg(feature = "bench-fixtures")]
fn prepare_inputs() -> (
    Arc<msphf_orchestrator::AnchorInstanceParts<'static>>,
    Arc<msphf_orchestrator::JoinerKGenResult>,
    Arc<BTreeMap<u64, Value>>,
    Arc<BTreeSet<String>>,
) {
    let (parts, _params, joiner) = sample_parts_params_joiner();
    let (pop_pk, pop_sk) = sample_pop_keys();
    let (base_header, _, _) = header_ready_with_pop(&joiner, &parts, pop_pk.as_slice(), &pop_sk);

    let mut allowed = BTreeSet::new();
    allowed.insert("srx/v1-complete".to_string());

    (
        Arc::new(parts),
        Arc::new(joiner),
        Arc::new(base_header),
        Arc::new(allowed),
    )
}

#[cfg(feature = "bench-fixtures")]
fn ensure_srx_benchmarks(c: &mut Criterion) {
    let ttl = Duration::from_secs(60);
    let srx_max_bytes = 1_048_576; // matches DEFAULT_SRX_MAX_BYTES

    let (parts, joiner, header_micro, allowed_modes) = prepare_inputs();

    {
        let header = Arc::clone(&header_micro);
        let parts = Arc::clone(&parts);
        let joiner = Arc::clone(&joiner);
        let allowed = Arc::clone(&allowed_modes);
        c.bench_function("ensure_srx_relations/micro", move |b| {
            let header = Arc::clone(&header);
            let parts = Arc::clone(&parts);
            let joiner = Arc::clone(&joiner);
            let allowed = Arc::clone(&allowed);
            b.iter_batched(
                || SrxBenchHarness::new(ttl, srx_max_bytes),
                move |mut harness| {
                    let now = AcceptInstant::from_ticks(0);
                    harness
                        .ensure(
                            header.as_ref(),
                            parts.as_ref(),
                            joiner.as_ref(),
                            true,
                            Some(allowed.as_ref()),
                            now,
                        )
                        .expect("srx verification");
                },
                BatchSize::SmallInput,
            );
        });
    }

    {
        let header = Arc::clone(&header_micro);
        let parts = Arc::clone(&parts);
        let joiner = Arc::clone(&joiner);
        let allowed = Arc::clone(&allowed_modes);
        c.bench_function("ensure_srx_relations/micro_cached", move |b| {
            b.iter_batched(
                || {
                    let mut harness = SrxBenchHarness::new(ttl, srx_max_bytes);
                    let header = Arc::clone(&header);
                    let parts = Arc::clone(&parts);
                    let joiner = Arc::clone(&joiner);
                    let allowed = Arc::clone(&allowed);
                    let now = AcceptInstant::from_ticks(0);
                    harness
                        .ensure(
                            header.as_ref(),
                            parts.as_ref(),
                            joiner.as_ref(),
                            true,
                            Some(allowed.as_ref()),
                            now,
                        )
                        .expect("initial verification");
                    (harness, header, parts, joiner, allowed)
                },
                move |(mut harness, header, parts, joiner, allowed)| {
                    let now = AcceptInstant::from_ticks(0);
                    harness
                        .ensure(
                            header.as_ref(),
                            parts.as_ref(),
                            joiner.as_ref(),
                            true,
                            Some(allowed.as_ref()),
                            now,
                        )
                        .expect("cached verification");
                },
                BatchSize::SmallInput,
            );
        });
    }

    {
        let header = Arc::clone(&header_micro);
        let parts = Arc::clone(&parts);
        let joiner = Arc::clone(&joiner);
        let allowed = Arc::clone(&allowed_modes);
        c.bench_function("ensure_srx_relations/micro_burst4", move |b| {
            let header = Arc::clone(&header);
            let parts = Arc::clone(&parts);
            let joiner = Arc::clone(&joiner);
            let allowed = Arc::clone(&allowed);
            b.iter_batched(
                || SrxBenchHarness::new(ttl, srx_max_bytes),
                move |mut harness| {
                    for tick in 0..4 {
                        let now = AcceptInstant::from_ticks(tick);
                        harness
                            .ensure(
                                header.as_ref(),
                                parts.as_ref(),
                                joiner.as_ref(),
                                true,
                                Some(allowed.as_ref()),
                                now,
                            )
                            .expect("burst verification");
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
}

#[cfg(feature = "bench-fixtures")]
criterion_group!(srx, ensure_srx_benchmarks);
#[cfg(feature = "bench-fixtures")]
criterion_main!(srx);

#[cfg(not(feature = "bench-fixtures"))]
fn main() {
    eprintln!(
        "Enable the 'bench-fixtures' feature: cargo bench --features bench-fixtures --bench srx"
    );
}
