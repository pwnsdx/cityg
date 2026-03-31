use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../cityg-api/proto/cityg.proto");

    if env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        unsafe {
            env::set_var("PROTOC", protoc);
        }
    }

    prost_build::Config::new()
        .out_dir(env::var("OUT_DIR")?)
        .compile_protos(&["../cityg-api/proto/cityg.proto"], &["../cityg-api/proto"])?;

    Ok(())
}
