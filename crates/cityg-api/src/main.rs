#[cfg(all(not(test), not(coverage)))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cityg_api::run().await
}

#[cfg(any(test, coverage))]
fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn test_main_stub_runs() {
        super::main();
    }
}
