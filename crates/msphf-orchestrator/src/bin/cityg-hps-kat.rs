use std::{fs, path::PathBuf};

use clap::Parser;
use msphf_core::MsphfError;
use msphf_orchestrator::kat::{KatOutput, generate_from_plan_file};

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate RLWE/HPS KAT vectors")]
struct Args {
    /// Path to the input plan JSON
    #[arg(long)]
    plan: PathBuf,
    /// Optional output path (writes to stdout if omitted)
    #[arg(long)]
    out: Option<PathBuf>,
    /// Emit pretty-printed JSON
    #[arg(long, default_value_t = true)]
    pretty: bool,
}

fn main() {
    let args = Args::parse();
    if let Err(err) = run(args) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), MsphfError> {
    let output = generate_from_plan_file(&args.plan)?;
    write_output(&output, &args)
}

fn write_output(output: &KatOutput, args: &Args) -> Result<(), MsphfError> {
    let json = if args.pretty {
        serde_json::to_string_pretty(output)
    } else {
        serde_json::to_string(output)
    }
    .map_err(MsphfError::serialization)?;

    if let Some(path) = &args.out {
        fs::write(path, json).map_err(MsphfError::serialization)?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, anyhow};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> Result<PathBuf> {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_micros();
        let mut path = std::env::temp_dir();
        path.push(format!("cityg_{label}_{epoch}_{}", std::process::id()));
        Ok(path)
    }

    #[test]
    fn run_writes_output_file() -> Result<()> {
        let plan_path = temp_path("plan.json")?;
        let plan_json = json!({
            "params": {
                "msphf_crs_id": msphf_core::params::RLWE_CRS_ID_DEFAULT,
                "params_id": msphf_core::params::RLWE_PARAMS_ID_A1,
            },
            "anchor": {
                "gid": hex::encode([0x01; 32]),
                "cat": hex::encode([0x02; 32]),
                "tswe_salt_hash": hex::encode([0x03; 32]),
                "parent_root": hex::encode([0x04; 32]),
                "join_delta_root": hex::encode([0x05; 32]),
                "revoked_since_prev_root": hex::encode([0x06; 32]),
                "revoked_root": hex::encode([0x07; 32]),
                "pox_r_commit": serde_json::Value::Null,
            },
            "header": {
                "104": hex::encode(b"ml-kem-768"),
                "105": "9618a9b7000fc8e4742ea89464598814780565fb3137560bdff70a3f082cd8d72d5ce8a886e6c61be355bb8529a9b12f2a717401428c07882f23946282b153b37894354373d1f811001cb30b673278b6bcfd1891e5b69614378dbfbc288483c309e640d9e42981d29b26957eaba252b7949849f001eb8b87713c9d817236308151fbe6436a66b1f753b0e73530eae1c3b70c43cca0cc00b355c84ac3002a448e0c73c622a6e41c5f5e336f0de127b029c6a091b0f93968931ccb87eccdcca887a2f533b63c81ff1c2258945241f348e9953651e702befc71b3537eba3649b51b04c3706fca3c30a9d4927e6aa195462a58c87a4f396795b0a729dca48f393e5ef5a9ab15cdf8b5afffa25f3242650bc7c481973ddd822def0a87aa84cc75bbbdd1e1661d37bef7391e88bb7d79d5670ff054de784c5279112f4682e22907afb9a7f327c74076726bc938db169b1c758cced2497c03b593f9047057a1d0842952abb5a5075a34b873fbc4705c897281b16f3a3850311c71adec81e77932769795a0e2741c5936f16aca49da62340cc11a95cd73c6955ed1aed1f55b35d76d835b5e92902d76638b0ea09a36f66e5f190dc49655b9a00c136a5b05913ca64cc265a73e464690d12a288a39728ee5523d67bf9a588cac8916a761a8586acfde36712f9699ef7bc3db18bccf7a09817906232ab8e8c49b53ba2522567492a21a24c69eefd0cad4e7406719a0e5d56d95bcbafb170394d39a6563b4ee8c9d6aa206e4ba649368130e6ca1c4a1742067be1cc49490461adbb81b94a8abe81110df3642b0eb1f6c12bdb22a2746f837db4b88c40c843d73a046b78d4d44c3b49442e63509f7070a281246f8cb9152a32852b759e86ab507e870fabb27e504cf6c46854c32a839d4017380c1710809f17bb4e6e95a5b45bedd37b1db330f25724399b59961ec34e489af0fc5bf341ba503d6c7c0e80c44caa245e16762d67cb90290ef023aaba3cf33cb5d6fb521fd0853029a0215c5b68317871b33048ff074b0a56b49f1b367922d6a8a8603ac5060f859f9469678d422e1e6494380b270fb5942c08ac43869627c06c554976f83434d90b5d1d156178a16fbf18fc9a084dbc4997ad1214bf202c071c7f45969b3b67e00b948c3936ce3e47430a03973274b0290b7f53801c82470a0d0ac34039081fc42a193a2c569a6b67578d871ad0da6914891ce2176bb0ec4b1efd8c9f3a3bad20a85813a1240b68ab570b1f350b2b1217ce3b3cdf4eb3b076b6ae6d067682ac90ab4a839a79cb8b690e9f868704a7681fb3f7635076a132f26284c72b38801064d9eea8b8b14220a935b588762ebf5c771d01db14a811f34503168aa93b34aa77cb721d06d42875ff2072b77bbaafc273d221b20da841b7cb93419429413a9264fe83948535f807bab784161b73a595283329f689ad6e83c1ba6a513c87aebc3c104652c2b914785c770b959312f6a756670a4d6645de1e87dc0c3192064c4ef841d6bc776367a82b83898283500e685a3c4113d4bb87f1eb1a3d377a5c7232d53e8620c248e218bb17a415b9934a9932236c2b434b55a5e9947961044748589a821b954ae90c009bbbc72f7bea32b9f39f7b0cbc510e5ce48c6a3852b34325811f73e129889f1bcedeed3f27ac19ce02941cb"
            },
            "rho": hex::encode([0x08; 32]),
            "seed_drbg": hex::encode([0x09; 32]),
            "cases": [{
                "id": "case-0",
                "branch": "A",
            }],
        });
        let plan_bytes = serde_json::to_vec(&plan_json)?;
        fs::write(&plan_path, plan_bytes)?;

        let out_path = temp_path("out.json")?;
        let args = Args {
            plan: plan_path.clone(),
            out: Some(out_path.clone()),
            pretty: false,
        };
        run(args)?;
        let written = fs::read_to_string(&out_path)?;
        assert!(written.contains("\"cases\""));

        let _ = fs::remove_file(plan_path);
        let _ = fs::remove_file(out_path);
        Ok(())
    }

    #[test]
    fn run_reports_invalid_plan() -> Result<()> {
        let plan_path = temp_path("bad.json")?;
        fs::write(&plan_path, b"{")?;
        let args = Args {
            plan: plan_path.clone(),
            out: None,
            pretty: true,
        };
        let err = match run(args) {
            Err(e) => e,
            Ok(_) => return Err(anyhow!("expected run to fail")),
        };
        assert!(err.to_string().contains("serialization"));
        let _ = fs::remove_file(plan_path);
        Ok(())
    }
}
