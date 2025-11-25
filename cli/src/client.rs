use crate::error::{CliError, Result};
use reqwest::Response;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(format!("lay-cli/{}", env!("CARGO_PKG_VERSION")))
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

    pub async fn get<R>(&self, path: &str) -> Result<R>
    where
        R: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.get(&url).send().await?;

        self.handle_response(response).await
    }

    pub async fn get_with_token<R>(&self, path: &str, token: &str) -> Result<R>
    where
        R: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        self.handle_response(response).await
    }

    async fn handle_response<R>(&self, response: Response) -> Result<R>
    where
        R: DeserializeOwned,
    {
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(CliError::ApiError {
                status,
                message: if error_text.is_empty() {
                    "No error details".to_string()
                } else {
                    error_text
                },
            });
        }

        response.json().await.map_err(Into::into)
    }
}
