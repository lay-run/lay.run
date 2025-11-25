use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::{
    user::User,
    verification_code::{VerificationCode, VerificationCodeType},
};

const MAX_VERIFICATION_ATTEMPTS: i32 = 5;
const CODE_EXPIRY_MINUTES: i64 = 10;
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

    /// Hash a password using Argon2
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                tracing::error!("Failed to hash password: {:?}", e);
                AppError::PasswordHashFailed
            })?
            .to_string();

        Ok(password_hash)
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<()> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e| {
            tracing::error!("Failed to parse password hash: {:?}", e);
            AppError::InvalidCredentials
        })?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::InvalidCredentials)
    }

    /// Generate a 6-digit verification code
    pub fn generate_verification_code(&self) -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(0..1000000))
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

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
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
    pub async fn register_user(&self, email: &str, password: &str) -> Result<User> {
        // Validate email format
        if !self.is_valid_email(email) {
            return Err(AppError::InvalidEmail);
        }

        // Validate password strength
        if !self.is_strong_password(password) {
            return Err(AppError::WeakPassword);
        }

        // Check if user already exists
        if self.find_user_by_email(email).await.is_ok() {
            return Err(AppError::UserAlreadyExists);
        }

        // Hash password
        let password_hash = self.hash_password(password)?;

        // Create user
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, password_hash, is_verified)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(email)
        .bind(&password_hash)
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
            r#"
            INSERT INTO verification_codes (user_id, code, code_type, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
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
            r#"
            SELECT * FROM verification_codes
            WHERE user_id = $1 AND code_type = $2 AND is_used = false
            ORDER BY created_at DESC
            LIMIT 1
            "#,
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

    /// Validate password strength
    pub(crate) fn is_strong_password(&self, password: &str) -> bool {
        password.len() >= 8
            && password.chars().any(|c| c.is_uppercase())
            && password.chars().any(|c| c.is_lowercase())
            && password.chars().any(|c| c.is_numeric())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::User;

    #[tokio::test]
    async fn test_password_hashing_and_verification() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool, "test-secret".to_string());
        let password = "SecurePassword123";

        // Hash password
        let hash = service.hash_password(password).expect("Failed to hash password");

        // Verify correct password
        assert!(service.verify_password(password, &hash).is_ok());

        // Verify incorrect password fails
        assert!(service.verify_password("WrongPassword", &hash).is_err());
    }

    #[tokio::test]
    async fn test_password_hashing_generates_different_hashes() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool, "test-secret".to_string());
        let password = "SecurePassword123";

        let hash1 = service.hash_password(password).expect("Failed to hash password");
        let hash2 = service.hash_password(password).expect("Failed to hash password");

        // Same password should generate different hashes (due to salt)
        assert_ne!(hash1, hash2);

        // Both hashes should verify the same password
        assert!(service.verify_password(password, &hash1).is_ok());
        assert!(service.verify_password(password, &hash2).is_ok());
    }

    #[tokio::test]
    async fn test_verification_code_format() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool, "test-secret".to_string());

        for _ in 0..100 {
            let code = service.generate_verification_code();

            // Code should be exactly 6 digits
            assert_eq!(code.len(), 6);

            // Code should only contain digits
            assert!(code.chars().all(|c| c.is_numeric()));

            // Code should be a valid number
            assert!(code.parse::<u32>().is_ok());
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
    async fn test_password_strength_validation() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool, "test-secret".to_string());

        // Strong passwords
        assert!(service.is_strong_password("SecurePass123"));
        assert!(service.is_strong_password("MyP@ssw0rd"));
        assert!(service.is_strong_password("ValidPassword1"));

        // Weak passwords
        assert!(!service.is_strong_password("short1A")); // Too short
        assert!(!service.is_strong_password("alllowercase123")); // No uppercase
        assert!(!service.is_strong_password("ALLUPPERCASE123")); // No lowercase
        assert!(!service.is_strong_password("NoNumbers")); // No numbers
        assert!(!service.is_strong_password("")); // Empty
    }

    #[tokio::test]
    async fn test_jwt_token_generation_and_verification() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let service = AuthService::new(pool, "test-secret-key-for-jwt-signing".to_string());

        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            is_verified: true,
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
            password_hash: "hash".to_string(),
            is_verified: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let token = other_service
            .generate_jwt(&user)
            .expect("Failed to generate JWT");

        // Verification with different service should fail
        assert!(service.verify_jwt(&token).is_err());
    }
}

