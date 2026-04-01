use cityg_api_schema::pb::{
    ConfigureWindowRequest, ConfigureWindowResponse, GetTelemetryRequest, GetTelemetryResponse,
    GetWindowRequest, GetWindowResponse,
};
use cityg_client::ClientEpochBundle;

use crate::{CitygApiClient, Error, build_http_error};

impl CitygApiClient {
    pub async fn health(&self) -> Result<(), Error> {
        let url = format!("{}/health", self.base_url);
        let response = self.http.get(url).send().await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.bytes().await?.to_vec();
            Err(build_http_error(status, body))
        }
    }

    pub async fn window(&self) -> Result<GetWindowResponse, Error> {
        self.post_proto("/v1/window", GetWindowRequest {}).await
    }

    pub async fn telemetry(&self) -> Result<GetTelemetryResponse, Error> {
        self.post_proto("/v1/telemetry", GetTelemetryRequest {})
            .await
    }

    pub async fn configure_window(
        &self,
        h_max: Option<u32>,
        ttl_ms: Option<u32>,
    ) -> Result<ConfigureWindowResponse, Error> {
        let request = ConfigureWindowRequest { h_max, ttl_ms };
        self.post_proto("/v1/config/window", request).await
    }

    #[cfg(any(debug_assertions, feature = "debug-api"))]
    pub async fn debug_seed_window_head(&self, bundle: &ClientEpochBundle) -> Result<(), Error> {
        let bytes = bundle.to_cbor()?;
        let request = cityg_api_schema::pb::SeedHeadRequest { bundle_cbor: bytes };
        let _: cityg_api_schema::pb::SeedHeadResponse =
            self.post_proto("/v1/debug/window/seed", request).await?;
        Ok(())
    }
}
