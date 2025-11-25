use std::time::Duration;

use reqwest::Response;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{CliError, Result};

pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: String) -> Result<Self> {
        // Build a descriptive user-agent with OS information
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let user_agent = format!("lay-cli/{} ({}/{})", env!("CARGO_PKG_VERSION"), os, arch);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(user_agent)
            .build()?;

        Ok(Self { client, base_url })
    }

    pub async fn post<T, R>(&self, path: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.post(&url).json(body).send().await?;

        self.handle_response(response).await
    }

    async fn handle_response<R>(&self, response: Response) -> Result<R>
    where
        R: DeserializeOwned,
    {
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();

            // Try to parse JSON error response
            let message = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&error_text) {
                // Extract error message from {"error": "..."} or {"message": "..."}
                json.get("error")
                    .or_else(|| json.get("message"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| error_text)
            } else if error_text.is_empty() {
                "no error details".to_string()
            } else {
                error_text
            };

            return Err(CliError::ApiError { status, message });
        }

        response.json().await.map_err(Into::into)
    }
}
