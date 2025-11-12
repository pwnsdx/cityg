use std::env;

fn main() {
    println!("cargo:rerun-if-changed=../cityg-api/proto/cityg.proto");

    // Ensure a protoc binary is available when CI runners don't provide one.
    if env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()
            .expect("Failed to locate vendored protoc binary");
        unsafe {
            env::set_var("PROTOC", protoc);
        }
    }

    prost_build::Config::new()
        .out_dir(env::var("OUT_DIR").expect("OUT_DIR not set"))
        .compile_protos(&["../cityg-api/proto/cityg.proto"], &["../cityg-api/proto"])
        .expect("Failed to compile protobuf definitions");
}
