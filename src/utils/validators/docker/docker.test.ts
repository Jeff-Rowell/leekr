import { validateDockerCredentials } from './docker';

// Mock fetch for testing validation scenarios
const originalFetch = global.fetch;

describe('validateDockerCredentials', () => {
    beforeEach(() => {
        // Reset fetch mock before each test
        global.fetch = originalFetch;
    });

    afterAll(() => {
        // Restore original fetch after all tests
        global.fetch = originalFetch;
    });

    const validDockerConfig = JSON.stringify({
        auths: {
            "registry.example.com": {
                auth: "dGVzdDp0ZXN0", // base64 for test:test
                username: "test",
                password: "test",
                email: "test@example.com"
            }
        }
    });

    const validDockerConfigWithMultipleRegistries = JSON.stringify({
        auths: {
            "registry.example.com": {
                auth: "dGVzdDp0ZXN0",
                username: "test",
                password: "test"
            },
            "another.registry.com": {
                auth: "YWRtaW46YWRtaW4=", // base64 for admin:admin
                username: "admin",
                password: "admin"
            }
        }
    });

    const dockerConfigWithUsernamePasswordOnly = JSON.stringify({
        auths: {
            "registry.example.com": {
                username: "testuser",
                password: "testpass",
                email: "test@example.com"
            }
        }
    });

    const dockerConfigWithAuthOnly = JSON.stringify({
        auths: {
            "registry.example.com": {
                auth: "dGVzdHVzZXI6dGVzdHBhc3M=" // base64 for testuser:testpass
            }
        }
    });

    test('should validate credentials successfully with mock response', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 200,
            text: () => Promise.resolve('{}')
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(true);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('');
        
        expect(global.fetch).toHaveBeenCalledWith(
            'https://registry.example.com/v2/',
            expect.objectContaining({
                method: 'GET',
                headers: expect.objectContaining({
                    'Authorization': 'Basic dGVzdDp0ZXN0',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                })
            })
        );
    });

    test('should handle Docker Hub registry normalization', async () => {
        const dockerHubConfig = JSON.stringify({
            auths: {
                "docker.io": {
                    auth: "dGVzdDp0ZXN0"
                }
            }
        });

        global.fetch = jest.fn().mockResolvedValue({
            status: 200,
            text: () => Promise.resolve('{}')
        });

        const result = await validateDockerCredentials(dockerHubConfig);
        
        expect(result.valid).toBe(true);
        expect(global.fetch).toHaveBeenCalledWith(
            'https://index.docker.io/v2/',
            expect.any(Object)
        );
    });

    test('should handle bearer authentication flow', async () => {
        // First call returns 401 with WWW-Authenticate header
        const firstCall = jest.fn().mockResolvedValue({
            status: 401,
            headers: {
                get: jest.fn().mockReturnValue('Bearer realm="https://auth.docker.io/token",service="registry.docker.io"')
            }
        });

        // Second call (to token endpoint) returns 200
        const secondCall = jest.fn().mockResolvedValue({
            status: 200,
            json: () => Promise.resolve({ token: 'test-token' })
        });

        global.fetch = jest.fn()
            .mockImplementationOnce(firstCall)
            .mockImplementationOnce(secondCall);

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(true);
        expect(global.fetch).toHaveBeenCalledTimes(2);
        
        // Check token endpoint was called
        expect(global.fetch).toHaveBeenCalledWith(
            expect.stringContaining('https://auth.docker.io/token'),
            expect.any(Object)
        );
    });

    test('should reject invalid JSON', async () => {
        const invalidJson = '{invalid json}';
        
        const result = await validateDockerCredentials(invalidJson);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid JSON format');
    });

    test('should reject missing auths object', async () => {
        const missingAuths = JSON.stringify({
            version: "1.0"
        });
        
        const result = await validateDockerCredentials(missingAuths);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Missing auths object');
    });

    test('should reject empty auths object', async () => {
        const emptyAuths = JSON.stringify({
            auths: {}
        });
        
        const result = await validateDockerCredentials(emptyAuths);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('No registry configurations found');
    });

    test('should reject auth without credentials', async () => {
        const noCredentials = JSON.stringify({
            auths: {
                "registry.example.com": {
                    email: "test@example.com"
                }
            }
        });
        
        const result = await validateDockerCredentials(noCredentials);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Missing auth credentials');
    });

    test('should skip example registries', async () => {
        const exampleRegistry = JSON.stringify({
            auths: {
                "https://index.docker.io/v1/": {
                    auth: "dGVzdDp0ZXN0"
                }
            }
        });
        
        const result = await validateDockerCredentials(exampleRegistry);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle username/password only configuration', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 200,
            text: () => Promise.resolve('{}')
        });

        const result = await validateDockerCredentials(dockerConfigWithUsernamePasswordOnly);
        
        expect(result.valid).toBe(true);
        expect(result.type).toBe('REGISTRY');
        
        // Should create base64 auth from username/password
        expect(global.fetch).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({
                headers: expect.objectContaining({
                    'Authorization': expect.stringMatching(/^Basic [A-Za-z0-9+/]+=*$/)
                })
            })
        );
    });

    test('should handle auth only configuration', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 200,
            text: () => Promise.resolve('{}')
        });

        const result = await validateDockerCredentials(dockerConfigWithAuthOnly);
        
        expect(result.valid).toBe(true);
        expect(result.type).toBe('REGISTRY');
        
        expect(global.fetch).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({
                headers: expect.objectContaining({
                    'Authorization': 'Basic dGVzdHVzZXI6dGVzdHBhc3M='
                })
            })
        );
    });

    test('should handle 401 unauthorized response', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 401,
            headers: {
                get: jest.fn().mockReturnValue(null) // No WWW-Authenticate header
            }
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle 404 not found response', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 404
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle network errors', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('Verification failed'));

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('Verification failed');
    });

    test('should handle multiple registries and return valid on first success', async () => {
        // First registry fails, second succeeds
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 401,
                headers: { get: jest.fn().mockReturnValue(null) }
            })
            .mockResolvedValueOnce({
                status: 200,
                text: () => Promise.resolve('{}')
            });

        const result = await validateDockerCredentials(validDockerConfigWithMultipleRegistries);
        
        expect(result.valid).toBe(true);
        expect(result.type).toBe('REGISTRY');
    });

    test('should handle invalid base64 auth gracefully', async () => {
        const invalidBase64Config = JSON.stringify({
            auths: {
                "registry.example.com": {
                    auth: "invalid-base64!@#"
                }
            }
        });
        
        const result = await validateDockerCredentials(invalidBase64Config);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle bearer auth with missing realm', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 401,
            headers: {
                get: jest.fn().mockReturnValue('Bearer service="registry.docker.io"') // Missing realm
            }
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle bearer auth token request failure', async () => {
        // First call returns 401 with WWW-Authenticate header
        const firstCall = jest.fn().mockResolvedValue({
            status: 401,
            headers: {
                get: jest.fn().mockReturnValue('Bearer realm="https://auth.docker.io/token",service="registry.docker.io"')
            }
        });

        // Second call (to token endpoint) returns 401
        const secondCall = jest.fn().mockResolvedValue({
            status: 401
        });

        global.fetch = jest.fn()
            .mockImplementationOnce(firstCall)
            .mockImplementationOnce(secondCall);

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle general errors during validation', async () => {
        // Mock a scenario where parsing fails after structure validation
        const mockError = new Error('Verification failed');
        
        global.fetch = jest.fn().mockImplementation(() => {
            throw mockError;
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('Verification failed');
    });

    test('should handle credentials mismatch between auth and username/password', async () => {
        const mismatchedCredentials = JSON.stringify({
            auths: {
                "registry.example.com": {
                    auth: "dGVzdDp0ZXN0", // base64 for test:test
                    username: "different",
                    password: "different"
                }
            }
        });

        global.fetch = jest.fn().mockResolvedValue({
            status: 200,
            text: () => Promise.resolve('{}')
        });

        const result = await validateDockerCredentials(mismatchedCredentials);
        
        expect(result.valid).toBe(true);
        // Should use auth field values when credentials mismatch
        expect(global.fetch).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({
                headers: expect.objectContaining({
                    'Authorization': 'Basic dGVzdDp0ZXN0'
                })
            })
        );
    });

    test('should handle registry URL with trailing slash', async () => {
        const configWithTrailingSlash = JSON.stringify({
            auths: {
                "registry.example.com/": {
                    auth: "dGVzdDp0ZXN0"
                }
            }
        });

        global.fetch = jest.fn().mockResolvedValue({
            status: 200,
            text: () => Promise.resolve('{}')
        });

        const result = await validateDockerCredentials(configWithTrailingSlash);
        
        expect(result.valid).toBe(true);
        expect(global.fetch).toHaveBeenCalledWith(
            'https://registry.example.com/v2/',
            expect.any(Object)
        );
    });

    test('should handle 200 response with invalid JSON body', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 200,
            text: () => Promise.resolve('not valid json{')
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(true); // Should still be valid even with invalid JSON
        expect(result.type).toBe('REGISTRY');
    });

    test('should handle 401 response with unauthorized message', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('unauthorized access'));

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('Invalid credentials - authentication failed');
    });

    test('should handle malformed WWW-Authenticate header', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 401,
            headers: {
                get: jest.fn().mockReturnValue('Bearer invalid-header-format')
            }
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle bearer auth with error in token request', async () => {
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 401,
                headers: {
                    get: jest.fn().mockReturnValue('Bearer realm="https://auth.docker.io/token",service="registry.docker.io"')
                }
            })
            .mockRejectedValueOnce(new Error('Token request failed'));

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle top-level error in main validation function', async () => {
        // Create a malformed auth config that causes an error in the main try-catch
        const malformedConfig = JSON.stringify({
            auths: {
                "registry.example.com": "not-an-object"
            }
        });

        const result = await validateDockerCredentials(malformedConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toBe('Invalid auth object');
    });

    test('should handle invalid base64 in extractCredentials', async () => {
        const invalidBase64Config = JSON.stringify({
            auths: {
                "registry.example.com": {
                    auth: "invalid-base64-format!"
                }
            }
        });

        const result = await validateDockerCredentials(invalidBase64Config);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle auth with empty credentials after decoding', async () => {
        const emptyCredsConfig = JSON.stringify({
            auths: {
                "registry.example.com": {
                    auth: "Og==" // base64 for ":"
                }
            }
        });

        const result = await validateDockerCredentials(emptyCredsConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle registry URL that starts with http://', async () => {
        const httpRegistryConfig = JSON.stringify({
            auths: {
                "http://registry.example.com": {
                    auth: "dGVzdDp0ZXN0"
                }
            }
        });

        global.fetch = jest.fn().mockResolvedValue({
            status: 200,
            text: () => Promise.resolve('{}')
        });

        const result = await validateDockerCredentials(httpRegistryConfig);
        
        expect(result.valid).toBe(true);
        expect(global.fetch).toHaveBeenCalledWith(
            'http://registry.example.com/v2/',
            expect.any(Object)
        );
    });

    test('should handle other HTTP status codes', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 500
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle bearer auth with missing username (empty account parameter)', async () => {
        const configWithNoUsername = JSON.stringify({
            auths: {
                "registry.example.com": {
                    auth: "dGVzdDp0ZXN0" // base64 for test:test, but no explicit username field
                }
            }
        });

        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 401,
                headers: {
                    get: jest.fn().mockReturnValue('Bearer realm="https://auth.docker.io/token",service="registry.docker.io"')
                }
            })
            .mockResolvedValueOnce({
                status: 200
            });

        const result = await validateDockerCredentials(configWithNoUsername);
        
        expect(result.valid).toBe(true);
        expect(global.fetch).toHaveBeenCalledWith(
            expect.stringContaining('account=test'), // Should use decoded username from auth
            expect.any(Object)
        );
    });

    test('should handle WWW-Authenticate header with insufficient parts', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 401,
            headers: {
                get: jest.fn().mockReturnValue('Bearer') // Only one part, missing parameters
            }
        });

        const result = await validateDockerCredentials(validDockerConfig);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('REGISTRY');
        expect(result.error).toBe('No valid registry credentials found');
    });

    test('should handle bearer auth account parameter correctly', async () => {
        // This test exercises the credentials.username || '' line  
        const config = JSON.stringify({
            auths: {
                "registry.example.com": {
                    auth: "dGVzdDp0ZXN0" // base64 for test:test
                }
            }
        });

        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 401,
                headers: {
                    get: jest.fn().mockReturnValue('Bearer realm="https://auth.docker.io/token",service="registry.docker.io"')
                }
            })
            .mockResolvedValueOnce({
                status: 200
            });

        const result = await validateDockerCredentials(config);
        
        expect(result.valid).toBe(true);
        // Should include account parameter with username
        expect(global.fetch).toHaveBeenNthCalledWith(2,
            expect.stringContaining('account=test'),
            expect.any(Object)
        );
    });

    test('should handle top-level unexpected error in main try-catch', async () => {
        // Create a config that will cause an unexpected error in the main try block
        // We'll mock Object.entries to throw an error to trigger line 67
        const originalEntries = Object.entries;
        Object.entries = jest.fn().mockImplementation(() => {
            throw new Error('Unexpected system error');
        });

        const config = JSON.stringify({
            auths: {
                "registry.example.com": {
                    auth: "dGVzdDp0ZXN0"
                }
            }
        });

        const result = await validateDockerCredentials(config);
        
        expect(result.valid).toBe(false);
        expect(result.type).toBe('unknown');
        expect(result.error).toEqual(new Error('Unexpected system error'));

        // Restore original function
        Object.entries = originalEntries;
    });

});