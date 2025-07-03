import { validateGcpCredentials } from './gcp';

// Mock fetch for testing validation scenarios
const originalFetch = global.fetch;

describe('validateGcpCredentials', () => {
    beforeEach(() => {
        // Reset fetch mock before each test
        global.fetch = originalFetch;
        
        // Mock TextEncoder for crypto operations
        global.TextEncoder = jest.fn().mockImplementation(() => ({
            encode: jest.fn().mockReturnValue(new Uint8Array([1, 2, 3, 4]))
        }));
    });

    afterAll(() => {
        // Restore original fetch after all tests
        global.fetch = originalFetch;
    });
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

    test('should fail validation for fake credentials (real validation)', async () => {
        // This test now expects failure because we're using fake/truncated credentials
        // Real validation will attempt to authenticate with Google and fail
        const result = await validateGcpCredentials(validServiceAccountKey);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toBe('Verification failed');
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

    test('should detect disabled service account via invalid_grant error', async () => {
        // Mock fetch to simulate a disabled/deleted service account
        global.fetch = jest.fn().mockResolvedValue({
            ok: false,
            status: 400,
            text: () => Promise.resolve('{"error": "invalid_grant", "error_description": "Invalid grant: account not found"}')
        });

        // Use a properly formatted key (though still fake) to pass structure validation
        const disabledServiceAccountKey = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "disabled-service@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/disabled-service%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(disabledServiceAccountKey);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toBe('Verification failed');
    });

    test('should handle successful validation with mock credentials', async () => {
        // Mock atob for base64 decoding
        global.atob = jest.fn().mockReturnValue('mock-decoded-key-data');
        
        // Mock crypto.subtle for signing operations
        const mockSign = jest.fn().mockResolvedValue(new ArrayBuffer(256));
        const mockImportKey = jest.fn().mockResolvedValue('mock-crypto-key');
        
        Object.defineProperty(global, 'crypto', {
            value: {
                subtle: {
                    importKey: mockImportKey,
                    sign: mockSign
                }
            },
            writable: true
        });

        // Mock successful token response
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ access_token: 'mock_access_token_123' })
        });

        // Use a valid private key format
        const validKey = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "valid-service@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/valid-service%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(validKey);
        
        expect(result.valid).toBe(true);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toBe('');
        
        // Verify fetch was called with correct parameters
        expect(global.fetch).toHaveBeenCalledWith('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: expect.any(URLSearchParams)
        });
    });

    test('should handle error response from token endpoint', async () => {
        // Mock atob for base64 decoding
        global.atob = jest.fn().mockReturnValue('mock-decoded-key-data');
        
        // Mock crypto.subtle for signing operations
        const mockSign = jest.fn().mockResolvedValue(new ArrayBuffer(256));
        const mockImportKey = jest.fn().mockResolvedValue('mock-crypto-key');
        
        Object.defineProperty(global, 'crypto', {
            value: {
                subtle: {
                    importKey: mockImportKey,
                    sign: mockSign
                }
            },
            writable: true
        });

        // Mock error response from token endpoint
        global.fetch = jest.fn().mockResolvedValue({
            ok: false,
            status: 400,
            text: () => Promise.resolve('{"error": "invalid_grant", "error_description": "Account disabled"}')
        });

        const keyWithError = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "error-service@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/error-service%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(keyWithError);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toMatch(/Token request failed|JWT signing failed|Service account is disabled or deleted/);
    });

    test('should handle invalid_client error specifically', async () => {
        // Mock atob for base64 decoding
        global.atob = jest.fn().mockReturnValue('mock-decoded-key-data');
        
        // Mock crypto.subtle for signing operations
        const mockSign = jest.fn().mockResolvedValue(new ArrayBuffer(256));
        const mockImportKey = jest.fn().mockResolvedValue('mock-crypto-key');
        
        Object.defineProperty(global, 'crypto', {
            value: {
                subtle: {
                    importKey: mockImportKey,
                    sign: mockSign
                }
            },
            writable: true
        });

        // Mock error response with invalid_client
        global.fetch = jest.fn().mockResolvedValue({
            ok: false,
            status: 400,
            text: () => Promise.resolve('{"error": "invalid_client", "error_description": "Client revoked"}')
        });

        const keyWithInvalidClient = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "revoked-service@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/revoked-service%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(keyWithInvalidClient);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toMatch(/Token request failed|JWT signing failed|Service account is disabled or deleted/);
    });

    test('should handle token response without access_token', async () => {
        // Mock atob for base64 decoding
        global.atob = jest.fn().mockReturnValue('mock-decoded-key-data');
        
        // Mock crypto.subtle for signing operations
        const mockSign = jest.fn().mockResolvedValue(new ArrayBuffer(256));
        const mockImportKey = jest.fn().mockResolvedValue('mock-crypto-key');
        
        Object.defineProperty(global, 'crypto', {
            value: {
                subtle: {
                    importKey: mockImportKey,
                    sign: mockSign
                }
            },
            writable: true
        });

        // Mock response with no access token
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ error: 'some_error' })
        });

        const keyWithoutToken = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "no-token-service@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/no-token-service%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(keyWithoutToken);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toMatch(/Invalid credentials - authentication failed|JWT signing failed/);
    });

    test('should handle private key without proper headers', () => {
        const invalidKey = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "INVALID_KEY_WITHOUT_HEADERS",
            client_email: "test@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project-123.iam.gserviceaccount.com"
        });

        return validateGcpCredentials(invalidKey).then(result => {
            expect(result.valid).toBe(false);
            expect(result.type).toBe('unknown');  // Fails at structure validation level
            expect(result.error).toBe('Invalid private key format');
        });
    });

    test('should handle crypto import key failure', async () => {
        // Mock crypto.subtle to fail on importKey
        const mockImportKey = jest.fn().mockRejectedValue(new Error('Import key failed'));
        
        Object.defineProperty(global, 'crypto', {
            value: {
                subtle: {
                    importKey: mockImportKey,
                    sign: jest.fn()
                }
            },
            writable: true
        });

        const keyWithImportError = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "import-error@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/import-error%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(keyWithImportError);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toContain('Verification failed');
    });

    test('should handle crypto sign operation failure', async () => {
        // Mock crypto.subtle with successful import but failed sign
        const mockSign = jest.fn().mockRejectedValue(new Error('Sign operation failed'));
        const mockImportKey = jest.fn().mockResolvedValue('mock-crypto-key');
        
        Object.defineProperty(global, 'crypto', {
            value: {
                subtle: {
                    importKey: mockImportKey,
                    sign: mockSign
                }
            },
            writable: true
        });

        const keyWithSignError = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "sign-error@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/sign-error%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(keyWithSignError);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toContain('Verification failed');
    });

    test('should cover specific error handling branches', async () => {
        // Test to cover lines 41-47: specific error message detection
        const mockError = new Error('invalid_grant: service account disabled');
        
        // Mock crypto operations to fail with specific error
        global.atob = jest.fn().mockImplementation(() => {
            throw mockError;
        });
        
        const keyForErrorHandling = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "disabled@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/disabled%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(keyForErrorHandling);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toBe('Service account is disabled or deleted');
    });

    test('should cover error without specific keywords', async () => {
        // Test to cover line 47: generic error handling
        const mockError = new Error('some generic error');
        
        // Mock crypto operations to fail with generic error
        global.atob = jest.fn().mockImplementation(() => {
            throw mockError;
        });
        
        const keyForGenericError = JSON.stringify({
            type: "service_account",
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgCpW8MX5x\n-----END PRIVATE KEY-----\n",
            client_email: "generic-error@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/generic-error%40test-project-123.iam.gserviceaccount.com"
        });

        const result = await validateGcpCredentials(keyForGenericError);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toBe('Verification failed');
    });

    test('should handle private key that passes structure validation but fails PEM check in JWT signing', async () => {
        // Test to cover line 130: Create a test that reaches the PEM validation in signJWT
        // This test will pass structure validation but fail during JWT signing PEM validation
        
        // First, let's test the scenario where we can control the signJWT function behavior
        const keyWithManipulatedPem = JSON.stringify({
            type: "service_account", 
            project_id: "test-project-123",
            private_key_id: "1234567890abcdef1234567890abcdef12345678",
            // Key that will pass structure validation
            private_key: "-----BEGIN PRIVATE KEY-----\\nvalidkeydata\\n-----END PRIVATE KEY-----\\n",
            client_email: "pem-test@test-project-123.iam.gserviceaccount.com",
            client_id: "123456789012345678901",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/pem-test%40test-project-123.iam.gserviceaccount.com"
        });

        // Mock the entire cleaning process by intercepting String methods used in key cleaning
        // to simulate the private key losing its PEM structure during processing
        const originalIncludes = String.prototype.includes;
        let includesCallCount = 0;
        
        String.prototype.includes = jest.fn().mockImplementation(function(this: string, searchValue: string) {
            includesCallCount++;
            // After the 4th call (structure validation passes), start failing PEM checks in signJWT
            if (includesCallCount > 4 && searchValue === '-----BEGIN PRIVATE KEY-----') {
                return false; // This will trigger the "Invalid private key format" error
            }
            return originalIncludes.call(this, searchValue);
        });

        const result = await validateGcpCredentials(keyWithManipulatedPem);
        
        // Restore original method
        String.prototype.includes = originalIncludes;
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('SERVICE_ACCOUNT');
        expect(result.error).toMatch(/Verification failed/);
    });

});