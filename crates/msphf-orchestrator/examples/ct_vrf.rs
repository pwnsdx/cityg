use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use msphf_orchestrator::{MaskDigest, VrfCtx, lb, zk_vrf_impl};
use rand::Rng;
use rand::seq::SliceRandom;

const SAMPLE_COUNT: usize = 100_000;
const EPOCH_ID: [u8; 32] = [0xAB; 32];
const XK_HASH: [u8; 32] = [0x11; 32];
const RHO_COMMIT: [u8; 32] = [0x22; 32];
const SEED_BUNDLE_COMMIT: [u8; 32] = [0x33; 32];
const HP_COMMIT: [u8; 32] = [0x44; 32];
const PARENT_ROOT: [u8; 32] = [0x55; 32];
const JOIN_DELTA_ROOT: [u8; 32] = [0x66; 32];
const REVOKED_SINCE_ROOT: [u8; 32] = [0x77; 32];
const REVOKED_ROOT: [u8; 32] = [0x88; 32];
const FS_EPOCH_COMMIT: [u8; 32] = [0x99; 32];
const FS_DEV_PREV_COMMIT: [u8; 32] = [0xAA; 32];
const FS_DEV_COMMIT: [u8; 32] = [0xBB; 32];
const SRX_ROOT_SW: [u8; 32] = [0xCC; 32];
const FS_EC: u64 = 7;

fn demo_ctx<'a>() -> VrfCtx<'a> {
    VrfCtx {
        xk_hash: &XK_HASH,
        rho_commit: &RHO_COMMIT,
        seed_bundle_commit: &SEED_BUNDLE_COMMIT,
        crs_id: "demo/crs",
        hp_commit: &HP_COMMIT,
        params_id: "demo/params",
        parent_root: &PARENT_ROOT,
        join_delta_root: &JOIN_DELTA_ROOT,
        revoked_since_prev_root: &REVOKED_SINCE_ROOT,
        revoked_root: &REVOKED_ROOT,
        proof_mode: "lin+zkvrf",
        fs_policy_version: 7,
        meor_vrf_id: "lb-vrf/v1",
        fs_epoch_commit: &FS_EPOCH_COMMIT,
        fs_ec: FS_EC,
        fs_dev_prev_commit: &FS_DEV_PREV_COMMIT,
        fs_dev_commit: &FS_DEV_COMMIT,
        srx_root_sw: Some(&SRX_ROOT_SW),
        we_epoch_id: &EPOCH_ID,
    }
}

fn vrf_verify_ct(runner: &mut CtRunner, bench_rng: &mut BenchRng) {
    let params = match lb::generate_parameters([0x42; 32]) {
        Ok(p) => p,
        Err(_) => unreachable!("param generation should succeed"),
    };
    let (secret_payload, _public_payload) = match lb::generate_keypair(&params, [0x24; 32]) {
        Ok(kp) => kp,
        Err(_) => unreachable!("keypair generation should succeed"),
    };
    let ctx = demo_ctx();

    let masks_valid: (MaskDigest, MaskDigest) = ([0u8; 32], [0u8; 32]);
    let proof =
        match zk_vrf_impl::prove_result(&secret_payload, &ctx, (&masks_valid.0, &masks_valid.1)) {
            Ok(p) => p,
            Err(_) => unreachable!("prove should succeed"),
        };
    let public_payload = match lb::public_for_epoch(&secret_payload, ctx.we_epoch_id) {
        Ok(p) => p,
        Err(_) => unreachable!("public_for_epoch should succeed"),
    };

    assert!(
        match zk_vrf_impl::verify_result(
            &public_payload,
            &ctx,
            (&masks_valid.0, &masks_valid.1),
            &proof
        ) {
            Ok(r) => r,
            Err(_) => unreachable!("verify baseline should succeed"),
        },
        "baseline verify must succeed"
    );

    let mut samples: Vec<(Class, MaskDigest, MaskDigest)> = Vec::with_capacity(SAMPLE_COUNT * 2);

    for _ in 0..SAMPLE_COUNT {
        samples.push((Class::Left, masks_valid.0, masks_valid.1));

        let mut mask_b = masks_valid.1;
        let idx = bench_rng.r#gen::<usize>() % 32;
        mask_b[idx] ^= 0xFF;
        samples.push((Class::Right, masks_valid.0, mask_b));
    }

    samples.shuffle(bench_rng);

    for (class, mask_a, mask_b) in samples.into_iter() {
        runner.run_one(class, || {
            let _ = zk_vrf_impl::verify_result(&public_payload, &ctx, (&mask_a, &mask_b), &proof);
        });
    }
}

ctbench_main!(vrf_verify_ct);
