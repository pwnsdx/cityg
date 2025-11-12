#[cfg(not(feature = "native-app"))]
fn main() {
    eprintln!("cityg-gui native binary is disabled in this build.");
    eprintln!("Enable it with `cargo run -p cityg-gui --features native-app`.");
}

#[cfg(feature = "native-app")]
mod native;

#[cfg(feature = "native-app")]
fn main() {
    native::main();
}
