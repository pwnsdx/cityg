use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/cityg.proto");

    // CI runners (and some local setups) might not provide protoc, so default to the
    // vendored binary if the user hasn't configured PROTOC explicitly.
    if env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        unsafe {
            env::set_var("PROTOC", protoc);
        }
    }

    prost_build::Config::new()
        .out_dir(env::var("OUT_DIR")?)
        .compile_protos(&["proto/cityg.proto"], &["proto"])?;

    Ok(())
}
