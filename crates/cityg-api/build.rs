use std::env;

fn main() {
    println!("cargo:rerun-if-changed=proto/cityg.proto");

    // CI runners (and some local setups) might not provide protoc, so default to the
    // vendored binary if the user hasn't configured PROTOC explicitly.
    if env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()
            .expect("Failed to locate vendored protoc binary");
        unsafe {
            env::set_var("PROTOC", protoc);
        }
    }

    prost_build::Config::new()
        .out_dir(env::var("OUT_DIR").expect("OUT_DIR not set"))
        .compile_protos(&["proto/cityg.proto"], &["proto"])
        .expect("Failed to compile protobuf definitions");
}
