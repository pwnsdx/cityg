#[cfg(not(feature = "native-app"))]
fn main() {
    eprintln!("cityg-gui native binary is disabled in this build.");
    eprintln!("Enable it with `cargo run -p cityg-gui --features native-app`.");
}

#[cfg(feature = "native-app")]
mod native;

#[cfg(all(feature = "native-app", not(test)))]
fn main() {
    native::main();
}

#[cfg(all(feature = "native-app", test))]
fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn test_main_stub_runs() {
        super::main();
    }
}
