#[cfg(not(test))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cityg_api::run().await
}

#[cfg(test)]
fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn test_main_stub_runs() {
        super::main();
    }
}
