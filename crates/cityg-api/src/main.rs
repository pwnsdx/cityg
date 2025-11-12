#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cityg_api::run().await
}
