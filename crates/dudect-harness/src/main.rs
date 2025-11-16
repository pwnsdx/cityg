use capss::{
    field::{BaseField, FieldElement},
    smallwood::{self, SmallwoodConfig},
    types::{CapssPublicKey, CapssSignature, CapssStatement},
};
use clap::{Parser, ValueEnum};
use msphf_core::rlwe::{
    arithmetic::{barrett_reduce, montgomery_add, montgomery_reduce, montgomery_sub},
    constants::Q,
    matrix::expand_a,
};
use once_cell::sync::Lazy;
use rand::{
    Rng, SeedableRng,
    distributions::{Distribution, Standard},
    rngs::StdRng,
};
use std::{
    fmt,
    time::{Duration, Instant},
};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Timing harness for RLWE constant-time primitives"
)]
struct Args {
    /// Function to benchmark
    #[arg(long, value_enum)]
    target: Target,
    /// Number of samples per class (total samples ≈ 2 * samples)
    #[arg(long, default_value_t = 100_000)]
    samples: u64,
    /// Number of inner loop iterations to magnify timing
    #[arg(long, default_value_t = 128)]
    inner: u64,
    /// RNG seed (for reproducibility)
    #[arg(long, default_value_t = 0xDAD3_C7u64)]
    seed: u64,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Target {
    BarrettReduce,
    MontgomeryReduce,
    MontgomeryAdd,
    MontgomerySub,
    ExpandA,
    SmallwoodProve,
    SmallwoodVerify,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Target::BarrettReduce => "barrett_reduce",
            Target::MontgomeryReduce => "montgomery_reduce",
            Target::MontgomeryAdd => "montgomery_add",
            Target::MontgomerySub => "montgomery_sub",
            Target::ExpandA => "expand_a",
            Target::SmallwoodProve => "smallwood_prove",
            Target::SmallwoodVerify => "smallwood_verify",
        })
    }
}

#[derive(Default)]
struct Stats {
    pub sum: f64,
    pub sum_sq: f64,
    pub count: u64,
}

impl Stats {
    fn push(&mut self, value: f64) {
        self.sum += value;
        self.sum_sq += value * value;
        self.count += 1;
    }

    fn mean(&self) -> f64 {
        self.sum / self.count as f64
    }

    fn variance(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        let mean = self.mean();
        (self.sum_sq - self.count as f64 * mean * mean) / (self.count as f64 - 1.0)
    }
}

fn welch_t(a: &Stats, b: &Stats) -> f64 {
    let mean_diff = a.mean() - b.mean();
    let var_a = a.variance();
    let var_b = b.variance();
    let denom = (var_a / a.count as f64 + var_b / b.count as f64).sqrt();
    if denom == 0.0 { 0.0 } else { mean_diff / denom }
}

fn main() {
    let args = Args::parse();
    println!(
        "Running target '{}' with {} samples (inner loop {})",
        args.target, args.samples, args.inner
    );
    let mut rng = StdRng::seed_from_u64(args.seed);
    let mut class0 = Stats::default();
    let mut class1 = Stats::default();

    for _ in 0..args.samples {
        measure(&args, 0, &mut rng, &mut class0);
        measure(&args, 1, &mut rng, &mut class1);
    }

    println!("Class 0: mean {:.6} ns (n={})", class0.mean(), class0.count);
    println!("Class 1: mean {:.6} ns (n={})", class1.mean(), class1.count);
    let t = welch_t(&class0, &class1);
    println!("Welch t-statistic: {:.4}", t);
    println!("|t| > 4.5 is suspicious. Current |t| = {:.4}", t.abs());
}

fn measure(args: &Args, cls: u8, rng: &mut StdRng, stats: &mut Stats) {
    use std::hint::black_box;
    let inner = args.inner as usize;
    let elapsed = match args.target {
        Target::BarrettReduce => {
            let tight = (Q as i32) * (Q as i32) - 1;
            let mut inputs: Vec<i32> = (0..inner).map(|_| rng.gen_range(-tight..=tight)).collect();
            if cls == 1 {
                for val in &mut inputs {
                    *val ^= 1;
                }
            }
            let start = Instant::now();
            for &x in &inputs {
                black_box(barrett_reduce(black_box(x)));
            }
            start.elapsed()
        }
        Target::MontgomeryReduce => {
            let mut inputs: Vec<i32> = (0..inner).map(|_| Standard.sample(rng)).collect();
            if cls == 1 {
                for val in &mut inputs {
                    *val ^= 1;
                }
            }
            let start = Instant::now();
            for &x in &inputs {
                black_box(montgomery_reduce(black_box(x)));
            }
            start.elapsed()
        }
        Target::MontgomeryAdd | Target::MontgomerySub => {
            let mut inputs: Vec<(i16, i16)> = (0..inner)
                .map(|_| (Standard.sample(rng), Standard.sample(rng)))
                .collect();
            if cls == 1 {
                for (a, b) in &mut inputs {
                    *a ^= 1;
                    *b ^= 1;
                }
            }
            let start = Instant::now();
            match args.target {
                Target::MontgomeryAdd => {
                    for &(a, b) in &inputs {
                        black_box(montgomery_add(black_box(a), black_box(b)));
                    }
                }
                Target::MontgomerySub => {
                    for &(a, b) in &inputs {
                        black_box(montgomery_sub(black_box(a), black_box(b)));
                    }
                }
                _ => {}
            }
            start.elapsed()
        }
        Target::ExpandA => {
            let mut seeds = vec![[0u8; 32]; inner];
            for seed in &mut seeds {
                rng.fill(seed);
            }
            if cls == 1 {
                for seed in &mut seeds {
                    seed[0] ^= 0x01;
                }
            }
            let start = Instant::now();
            for seed in &seeds {
                black_box(expand_a(black_box(seed)));
            }
            start.elapsed()
        }
        Target::SmallwoodProve => {
            let fixture = smallwood_fixture(cls);
            let start = Instant::now();
            let proof = match smallwood::prove(&fixture.config, &fixture.statement) {
                Ok(p) => p,
                Err(_) => unreachable!(),
            };
            black_box(proof);
            start.elapsed()
        }
        Target::SmallwoodVerify => {
            let fixture = smallwood_fixture(cls);
            let start = Instant::now();
            match smallwood::verify(&fixture.config, &fixture.statement, &fixture.signature) {
                Ok(_) => {}
                Err(_) => unreachable!(),
            }
            start.elapsed()
        }
    };
    stats.push(duration_to_ns(elapsed));
}

fn duration_to_ns(d: Duration) -> f64 {
    d.as_secs_f64() * 1e9
}

struct SmallwoodFixture {
    config: SmallwoodConfig,
    statement: CapssStatement,
    signature: CapssSignature,
}

impl SmallwoodFixture {
    fn new(cls: u8) -> Self {
        let config = smallwood_config();
        let statement = smallwood_statement(cls);
        let proof = match smallwood::prove(&config, &statement) {
            Ok(p) => p,
            Err(_) => unreachable!(),
        };
        let signature = CapssSignature::from(proof);
        Self {
            config,
            statement,
            signature,
        }
    }
}

static SMALLWOOD_FIXTURES: Lazy<[SmallwoodFixture; 2]> =
    Lazy::new(|| [SmallwoodFixture::new(0), SmallwoodFixture::new(1)]);

fn smallwood_fixture(cls: u8) -> &'static SmallwoodFixture {
    &SMALLWOOD_FIXTURES[cls as usize]
}

fn smallwood_config() -> SmallwoodConfig {
    SmallwoodConfig {
        repetitions: 2,
        security_level: 128,
        polynomial_degree: 4,
        fs_domain: "dudect/smallwood".to_string(),
        nb_queries: 1,
        rho: 1,
    }
}

fn smallwood_statement(cls: u8) -> CapssStatement {
    let mut message = b"dudect-smallwood".to_vec();
    if cls == 1
        && let Some(first) = message.first_mut()
    {
        *first ^= 0x01;
    }

    CapssStatement {
        public_key: CapssPublicKey {
            iv: vec![FieldElement::from_base(BaseField::from(17u64 + cls as u64))],
            y: FieldElement::from_base(BaseField::from(33u64 + cls as u64)),
        },
        message,
    }
}
