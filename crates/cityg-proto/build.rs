use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/cityg_v2.proto");

    if env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: build scripts are single-threaded when this runs.
        unsafe {
            env::set_var("PROTOC", protoc);
        }
    }

    prost_build::Config::new()
        .out_dir(env::var("OUT_DIR")?)
        .compile_protos(&["proto/cityg_v2.proto"], &["proto"])?;

    Ok(())
}
