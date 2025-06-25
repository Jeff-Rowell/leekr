import { validateArtifactoryCredentials } from './artifactory';

// Mock fetch globally
global.fetch = jest.fn();

describe('validateArtifactoryCredentials', () => {
    const mockApiKey = 'abcdef1234567890123456789012345678901234567890123456789012345678901234';
    const mockUrl = 'example.jfrog.io';

    beforeEach(() => {
        jest.clearAllMocks();
        (global.fetch as jest.Mock).mockClear();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('validates successful credentials with URL', async () => {
        const mockResponse = {
            ok: true,
            json: () => Promise.resolve({ storageType: 'file-system' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateArtifactoryCredentials(mockApiKey, mockUrl);

        expect(result.valid).toBe(true);
        expect(result.error).toBe('');
        expect(result.url).toBe('https://example.jfrog.io');
        expect(result.tokenInfo).toBe('Valid Artifactory access token');
        expect(result.permissions).toEqual(['read']);
        expect(global.fetch).toHaveBeenCalledWith(
            'https://example.jfrog.io/artifactory/api/storageinfo',
            {
                method: 'GET',
                headers: {
                    'X-JFrog-Art-Api': mockApiKey,
                    'Content-Type': 'application/json'
                }
            }
        );
    });

    test('validates credentials with https URL already provided', async () => {
        const httpsUrl = 'https://example.jfrog.io';
        const mockResponse = {
            ok: true,
            json: () => Promise.resolve({ storageType: 'file-system' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateArtifactoryCredentials(mockApiKey, httpsUrl);

        expect(result.valid).toBe(true);
        expect(result.url).toBe('https://example.jfrog.io');
        expect(global.fetch).toHaveBeenCalledWith(
            'https://example.jfrog.io/artifactory/api/storageinfo',
            expect.any(Object)
        );
    });

    test('validates credentials with http URL', async () => {
        const httpUrl = 'http://example.jfrog.io';
        const mockResponse = {
            ok: true,
            json: () => Promise.resolve({ storageType: 'file-system' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateArtifactoryCredentials(mockApiKey, httpUrl);

        expect(result.valid).toBe(true);
        expect(result.url).toBe('http://example.jfrog.io');
        expect(global.fetch).toHaveBeenCalledWith(
            'http://example.jfrog.io/artifactory/api/storageinfo',
            expect.any(Object)
        );
    });

    test('returns error when no URL is provided', async () => {
        const result = await validateArtifactoryCredentials(mockApiKey);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Artifactory URL is required for validation');
        expect(global.fetch).not.toHaveBeenCalled();
    });

    test('returns error when URL is empty string', async () => {
        const result = await validateArtifactoryCredentials(mockApiKey, '');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Artifactory URL is required for validation');
        expect(global.fetch).not.toHaveBeenCalled();
    });

    test('handles 403 forbidden response', async () => {
        const mockResponse = {
            ok: false,
            status: 403,
            statusText: 'Forbidden'
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateArtifactoryCredentials(mockApiKey, mockUrl);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Token exists but lacks required permissions');
        expect(result.url).toBe('https://example.jfrog.io');
    });

    test('handles 401 unauthorized response', async () => {
        const mockResponse = {
            ok: false,
            status: 401,
            statusText: 'Unauthorized'
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateArtifactoryCredentials(mockApiKey, mockUrl);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid Artifactory access token');
        expect(result.url).toBe('https://example.jfrog.io');
    });

    test('handles other HTTP error responses', async () => {
        const mockResponse = {
            ok: false,
            status: 500,
            statusText: 'Internal Server Error'
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateArtifactoryCredentials(mockApiKey, mockUrl);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('HTTP 500: Internal Server Error');
        expect(result.url).toBe('https://example.jfrog.io');
    });

    test('handles network errors', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValue(networkError);

        const result = await validateArtifactoryCredentials(mockApiKey, mockUrl);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Network error');
    });

    test('handles non-Error exceptions', async () => {
        (global.fetch as jest.Mock).mockRejectedValue('String error');

        const result = await validateArtifactoryCredentials(mockApiKey, mockUrl);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Unknown validation error');
    });

    test('handles JSON parsing errors', async () => {
        const mockResponse = {
            ok: true,
            json: () => Promise.reject(new Error('Invalid JSON'))
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateArtifactoryCredentials(mockApiKey, mockUrl);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid JSON');
    });
});