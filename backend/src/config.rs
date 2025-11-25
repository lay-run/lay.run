use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
    pub jwt_secret: String,
    pub ses_from_email: String,
    pub ses_reply_to_email: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/backend".to_string());

        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()?;

        let jwt_secret = env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set in environment");

        let ses_from_email = env::var("SES_FROM_EMAIL")
            .expect("SES_FROM_EMAIL must be set in environment");

        let ses_reply_to_email = env::var("SES_REPLY_TO_EMAIL")
            .expect("SES_REPLY_TO_EMAIL must be set in environment");

        Ok(Self {
            database_url,
            host,
            port,
            jwt_secret,
            ses_from_email,
            ses_reply_to_email,
        })
    }

    pub fn server_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
