#[cfg(test)]
mod tests {
    use super::super::auth::AuthService;
    use sqlx::PgPool;

    fn create_test_service() -> AuthService {
        // Create a mock pool (won't be used for these tests)
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        AuthService::new(pool, "test-secret-key-for-jwt-signing".to_string())
    }

    #[test]
    fn test_password_hashing_and_verification() {
        let service = create_test_service();
        let password = "SecurePassword123";

        // Hash password
        let hash = service.hash_password(password).expect("Failed to hash password");

        // Verify correct password
        assert!(service.verify_password(password, &hash).is_ok());

        // Verify incorrect password fails
        assert!(service.verify_password("WrongPassword", &hash).is_err());
    }

    #[test]
    fn test_password_hashing_generates_different_hashes() {
        let service = create_test_service();
        let password = "SecurePassword123";

        let hash1 = service.hash_password(password).expect("Failed to hash password");
        let hash2 = service.hash_password(password).expect("Failed to hash password");

        // Same password should generate different hashes (due to salt)
        assert_ne!(hash1, hash2);

        // Both hashes should verify the same password
        assert!(service.verify_password(password, &hash1).is_ok());
        assert!(service.verify_password(password, &hash2).is_ok());
    }

    #[test]
    fn test_verification_code_format() {
        let service = create_test_service();

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

    #[test]
    fn test_email_validation() {
        let service = create_test_service();

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

    #[test]
    fn test_password_strength_validation() {
        let service = create_test_service();

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

    #[test]
    fn test_jwt_token_generation_and_verification() {
        use crate::models::user::User;
        use chrono::Utc;
        use uuid::Uuid;

        let service = create_test_service();

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

    #[test]
    fn test_jwt_verification_fails_for_invalid_token() {
        let service = create_test_service();

        // Invalid token should fail
        assert!(service.verify_jwt("invalid.token.here").is_err());

        // Token signed with different secret should fail
        let other_service = AuthService::new(
            PgPool::connect_lazy("postgres://localhost/test").unwrap(),
            "different-secret-key".to_string(),
        );

        use crate::models::user::User;
        use chrono::Utc;
        use uuid::Uuid;

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
