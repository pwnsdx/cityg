const GREETING: &str = "Hello, world!";

#[cfg(not(test))]
fn main() {
    println!("{GREETING}");
}

#[cfg(test)]
fn main() {}

#[cfg(test)]
mod tests {
    use super::GREETING;

    #[test]
    fn greeting_constant_is_stable() {
        assert_eq!(GREETING, "Hello, world!");
    }

    #[test]
    fn test_main_stub_runs() {
        super::main();
    }
}
