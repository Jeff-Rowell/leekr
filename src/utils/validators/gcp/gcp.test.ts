import { validateGcpCredentials } from './gcp';

describe('validateGcpCredentials', () => {
    const validServiceAccountKey = JSON.stringify({
        type: "service_account",
        project_id: "test-project-123",
        private_key_id: "1234567890abcdef1234567890abcdef12345678",
        private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC123...\n-----END PRIVATE KEY-----\n",
        client_email: "test-service@test-project-123.iam.gserviceaccount.com",
        client_id: "123456789012345678901",
        auth_uri: "https://accounts.google.com/o/oauth2/auth",
        token_uri: "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
        client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/test-service%40test-project-123.iam.gserviceaccount.com"
    });

    const testServiceAccountKey = JSON.stringify({
        type: "service_account",
        project_id: "authenticated-image-pulling",
        private_key_id: "test123",
        private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
        client_email: "image-pulling@authenticated-image-pulling.iam.gserviceaccount.com",
        client_id: "123",
        auth_uri: "https://accounts.google.com/o/oauth2/auth",
        token_uri: "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
        client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/test"
    });

    test('should validate a well-formed service account key', async () => {
        const result = await validateGcpCredentials(validServiceAccountKey);
        
        expect(result.valid).toBe(true);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toBe('');
    });

    test('should reject invalid JSON', async () => {
        const invalidJson = '{"type": "service_account", "project_id":';
        
        const result = await validateGcpCredentials(invalidJson);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid JSON format');
    });

    test('should reject non-service account type', async () => {
        const nonServiceAccount = JSON.stringify({
            type: "user_account",
            project_id: "test-project",
            private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            client_email: "test@example.com"
        });
        
        const result = await validateGcpCredentials(nonServiceAccount);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Not a service account');
    });

    test('should reject missing required fields', async () => {
        const missingFields = JSON.stringify({
            type: "service_account",
            project_id: "test-project"
        });
        
        const result = await validateGcpCredentials(missingFields);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Missing required fields');
    });

    test('should reject invalid project_id type', async () => {
        const invalidProjectId = JSON.stringify({
            type: "service_account",
            project_id: 123,
            private_key_id: "test",
            private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            client_email: "test@example.com"
        });
        
        const result = await validateGcpCredentials(invalidProjectId);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid project_id');
    });

    test('should reject invalid private_key_id type', async () => {
        const invalidPrivateKeyId = JSON.stringify({
            type: "service_account",
            project_id: "test-project",
            private_key_id: null,
            private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            client_email: "test@example.com"
        });
        
        const result = await validateGcpCredentials(invalidPrivateKeyId);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid private_key_id');
    });

    test('should reject invalid private_key type', async () => {
        const invalidPrivateKey = JSON.stringify({
            type: "service_account",
            project_id: "test-project",
            private_key_id: "test",
            private_key: 123,
            client_email: "test@example.com"
        });
        
        const result = await validateGcpCredentials(invalidPrivateKey);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid private_key');
    });

    test('should reject invalid client_email type', async () => {
        const invalidClientEmail = JSON.stringify({
            type: "service_account",
            project_id: "test-project",
            private_key_id: "test",
            private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            client_email: 123  // Invalid type - should be string
        });
        
        const result = await validateGcpCredentials(invalidClientEmail);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid client_email');
    });

    test('should reject invalid email format', async () => {
        const invalidEmailFormat = JSON.stringify({
            type: "service_account",
            project_id: "test-project",
            private_key_id: "test",
            private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            client_email: "invalid-email-format"
        });
        
        const result = await validateGcpCredentials(invalidEmailFormat);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid email format');
    });

    test('should reject invalid private key format', async () => {
        const invalidPrivateKeyFormat = JSON.stringify({
            type: "service_account",
            project_id: "test-project",
            private_key_id: "test",
            private_key: "invalid-private-key-format",
            client_email: "test@example.com"
        });
        
        const result = await validateGcpCredentials(invalidPrivateKeyFormat);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid private key format');
    });

    test('should reject test service account', async () => {
        const result = await validateGcpCredentials(testServiceAccountKey);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Test service account');
    });

    test('should handle general errors', async () => {
        // Pass a non-string value to trigger a general error
        const result = await validateGcpCredentials(null as any);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBeDefined();
    });
});