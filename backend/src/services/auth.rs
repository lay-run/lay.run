use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use totp_rs::{Secret, TOTP};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::user::User;
use crate::models::verification_code::{VerificationCode, VerificationCodeType};

const MAX_VERIFICATION_ATTEMPTS: i32 = 5;
const CODE_EXPIRY_MINUTES: i64 = 5;
const CODE_LENGTH: usize = 8;
const JWT_EXPIRY_DAYS: i64 = 30;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub email: String,
    pub exp: i64, // Expiration timestamp
    pub iat: i64, // Issued at timestamp
}

/// Authentication service handling all auth-related business logic
#[derive(Clone)]
pub struct AuthService {
    pool: PgPool,
    jwt_secret: String,
}

impl AuthService {
    /// Create a new auth service instance
    pub fn new(pool: PgPool, jwt_secret: String) -> Self {
        Self { pool, jwt_secret }
    }

    /// Generate a pronounceable verification code (CVCVCVCV pattern)
    pub fn generate_verification_code(&self) -> String {
        let mut rng = rand::thread_rng();
        let consonants = [
            'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'w',
            'x', 'z',
        ];
        let vowels = ['a', 'e', 'i', 'o', 'u'];

        let mut code = String::with_capacity(CODE_LENGTH);
        for i in 0..CODE_LENGTH {
            if i % 2 == 0 {
                // Consonant
                code.push(consonants[rng.gen_range(0..consonants.len())]);
            } else {
                // Vowel
                code.push(vowels[rng.gen_range(0..vowels.len())]);
            }
        }

        code.to_uppercase()
    }

    /// Generate JWT token for authenticated user
    pub fn generate_jwt(&self, user: &User) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::days(JWT_EXPIRY_DAYS);

        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        encode(&Header::default(), &claims, &EncodingKey::from_secret(self.jwt_secret.as_bytes()))
            .map_err(|e| {
                tracing::error!("Failed to generate JWT: {:?}", e);
                AppError::TokenGenerationFailed
            })
    }

    /// Verify JWT token and extract claims
    pub fn verify_jwt(&self, token: &str) -> Result<Claims> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|_| AppError::InvalidToken)
    }

    /// Register a new user
    pub async fn register_user(&self, email: &str) -> Result<User> {
        // Validate email format
        if !self.is_valid_email(email) {
            return Err(AppError::InvalidEmail);
        }

        // Check if user already exists
        if self.find_user_by_email(email).await.is_ok() {
            return Err(AppError::UserAlreadyExists);
        }

        // Create user
        let user = sqlx::query_as::<_, User>(
            r"
            INSERT INTO users (email, is_verified)
            VALUES ($1, $2)
            RETURNING *
            ",
        )
        .bind(email)
        .bind(false)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create user: {:?}", e);
            AppError::DatabaseError
        })?;

        Ok(user)
    }

    /// Create verification code for user
    pub async fn create_verification_code(
        &self,
        user_id: Uuid,
        code_type: VerificationCodeType,
    ) -> Result<String> {
        let code = self.generate_verification_code();
        let expires_at = Utc::now() + Duration::minutes(CODE_EXPIRY_MINUTES);

        sqlx::query(
            r"
            INSERT INTO verification_codes (user_id, code, code_type, expires_at)
            VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(user_id)
        .bind(&code)
        .bind(code_type.as_str())
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create verification code: {:?}", e);
            AppError::DatabaseError
        })?;

        Ok(code)
    }

    /// Verify a code
    pub async fn verify_code(
        &self,
        user_id: Uuid,
        code: &str,
        code_type: VerificationCodeType,
    ) -> Result<()> {
        // Fetch the verification code
        let mut verification_code = sqlx::query_as::<_, VerificationCode>(
            r"
            SELECT * FROM verification_codes
            WHERE user_id = $1 AND code_type = $2 AND is_used = false
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(user_id)
        .bind(code_type.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch verification code: {:?}", e);
            AppError::DatabaseError
        })?
        .ok_or(AppError::InvalidVerificationCode)?;

        // Check if code is valid
        if !verification_code.is_valid() {
            return Err(AppError::ExpiredVerificationCode);
        }

        // Increment attempts
        verification_code.attempts += 1;

        // Check attempts limit
        if verification_code.attempts > MAX_VERIFICATION_ATTEMPTS {
            self.mark_code_as_used(verification_code.id).await?;
            return Err(AppError::TooManyAttempts);
        }

        // Verify code
        if verification_code.code != code {
            // Update attempts
            sqlx::query("UPDATE verification_codes SET attempts = $1 WHERE id = $2")
                .bind(verification_code.attempts)
                .bind(verification_code.id)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to update verification code attempts: {:?}", e);
                    AppError::DatabaseError
                })?;

            return Err(AppError::InvalidVerificationCode);
        }

        // Mark code as used
        self.mark_code_as_used(verification_code.id).await?;

        // If email verification, mark user as verified
        if matches!(code_type, VerificationCodeType::EmailVerification) {
            self.mark_user_verified(user_id).await?;
        }

        Ok(())
    }

    /// Find user by email
    pub async fn find_user_by_email(&self, email: &str) -> Result<User> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::UserNotFound)
    }

    /// Find user by ID
    pub async fn find_user_by_id(&self, user_id: Uuid) -> Result<User> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::UserNotFound)
    }

    /// Mark verification code as used
    async fn mark_code_as_used(&self, code_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE verification_codes SET is_used = true WHERE id = $1")
            .bind(code_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to mark code as used: {:?}", e);
                AppError::DatabaseError
            })?;

        Ok(())
    }

    /// Mark user as verified
    async fn mark_user_verified(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE users SET is_verified = true, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to mark user as verified: {:?}", e);
                AppError::DatabaseError
            })?;

        Ok(())
    }

    /// Validate email format (basic validation)
    pub(crate) fn is_valid_email(&self, email: &str) -> bool {
        if email.len() < 6 {
            return false;
        }

        let at_pos = email.find('@');
        let dot_pos = email.rfind('.');

        match (at_pos, dot_pos) {
            (Some(at), Some(dot)) => {
                // Must have at least 1 char before @, and dot must be after @
                at > 0 && dot > at + 1 && dot < email.len() - 1
            }
            _ => false,
        }
    }

    /// Generate TOTP secret and provisioning URI
    pub fn generate_totp_secret(&self, email: &str) -> Result<(String, String)> {
        let secret = Secret::generate_secret();
        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            Some("lay.run".to_string()),
            email.to_string(),
        )
        .map_err(|e| {
            tracing::error!("Failed to create TOTP: {:?}", e);
            AppError::TotpGenerationFailed
        })?;

        let secret_str = secret.to_encoded().to_string();
        let uri = totp.get_url();

        Ok((secret_str, uri))
    }

    /// Verify TOTP code
    pub fn verify_totp(&self, secret: &str, code: &str) -> Result<()> {
        let secret_bytes = Secret::Encoded(secret.to_string()).to_bytes().map_err(|e| {
            tracing::error!("Failed to decode TOTP secret: {:?}", e);
            AppError::InvalidTotpSecret
        })?;

        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("lay.run".to_string()),
            "".to_string(),
        )
        .map_err(|e| {
            tracing::error!("Failed to create TOTP for verification: {:?}", e);
            AppError::InvalidTotpSecret
        })?;

        if totp.check_current(code).map_err(|e| {
            tracing::error!("TOTP verification failed: {:?}", e);
            AppError::InvalidTotpCode
        })? {
            Ok(())
        } else {
            Err(AppError::InvalidTotpCode)
        }
    }

    /// Enable TOTP for user
    pub async fn enable_totp(&self, user_id: Uuid, secret: &str) -> Result<()> {
        sqlx::query(
            "UPDATE users SET totp_secret = $1, totp_enabled = true, updated_at = NOW() WHERE id = $2",
        )
        .bind(secret)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to enable TOTP: {:?}", e);
            AppError::DatabaseError
        })?;

        Ok(())
    }

    /// Disable TOTP for user
    pub async fn disable_totp(&self, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE users SET totp_secret = NULL, totp_enabled = false, updated_at = NOW() WHERE id = $2",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to disable TOTP: {:?}", e);
            AppError::DatabaseError
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::User;

    #[tokio::test]
    async fn test_verification_code_format() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool, "test-secret".to_string());

        for _ in 0..100 {
            let code = service.generate_verification_code();

            // Code should be exactly CODE_LENGTH characters
            assert_eq!(code.len(), CODE_LENGTH);

            // Code should only contain letters
            assert!(code.chars().all(|c| c.is_alphabetic()));

            // Code should be uppercase
            assert!(code.chars().all(|c| c.is_uppercase()));

            // Verify CVCVCVCV pattern
            for (i, ch) in code.chars().enumerate() {
                if i % 2 == 0 {
                    // Even positions should be consonants
                    assert!(!['A', 'E', 'I', 'O', 'U'].contains(&ch));
                } else {
                    // Odd positions should be vowels
                    assert!(['A', 'E', 'I', 'O', 'U'].contains(&ch));
                }
            }
        }
    }

    #[tokio::test]
    async fn test_email_validation() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool, "test-secret".to_string());

        // Valid emails
        assert!(service.is_valid_email("user@example.com"));
        assert!(service.is_valid_email("test.user@domain.co.uk"));
        assert!(service.is_valid_email("user+tag@example.com"));

        // Invalid emails
        assert!(!service.is_valid_email("invalid"));
        assert!(!service.is_valid_email("@example.com"));
        assert!(!service.is_valid_email("user@"));
        assert!(!service.is_valid_email("user"));
        assert!(!service.is_valid_email(""));
    }

    #[tokio::test]
    async fn test_jwt_token_generation_and_verification() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool, "test-secret-key-for-jwt-signing".to_string());

        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            is_verified: true,
            totp_enabled: false,
            totp_secret: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Generate JWT
        let token = service.generate_jwt(&user).expect("Failed to generate JWT");

        // Verify JWT
        let claims = service.verify_jwt(&token).expect("Failed to verify JWT");

        // Check claims
        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.email, user.email);
        assert!(claims.exp > Utc::now().timestamp());
    }

    #[tokio::test]
    async fn test_jwt_verification_fails_for_invalid_token() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool.clone(), "test-secret".to_string());

        // Invalid token should fail
        assert!(service.verify_jwt("invalid.token.here").is_err());

        // Token signed with different secret should fail
        let other_service = AuthService::new(pool, "different-secret-key".to_string());

        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            is_verified: true,
            totp_enabled: false,
            totp_secret: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let token = other_service.generate_jwt(&user).expect("Failed to generate JWT");

        // Verification with different service should fail
        assert!(service.verify_jwt(&token).is_err());
    }
}
