import { validateAzureOpenAICredentials } from './azure_openai';
import { AzureOpenAIValidationResult } from '../../../types/azure_openai';

// Mock fetch
global.fetch = jest.fn();
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

describe('validateAzureOpenAICredentials', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    const mockApiKey = '3ztQKWPXQXGSWHrje6TkXPKhI6gFyq1kWpFtA46YzPB4t3FsEIzxJQQJ99BFACYeBjFXJ3w3AAABACOGXpos';
    const mockUrl = 'test-instance.openai.azure.com';

    test('should return invalid when no URL is provided', async () => {
        const result = await validateAzureOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            error: 'Azure OpenAI URL is required for validation'
        });
        expect(mockFetch).not.toHaveBeenCalled();
    });

    test('should validate successfully with correct API key and URL', async () => {
        const mockResponse = {
            data: [
                { id: 'gpt-35-turbo' },
                { id: 'text-embedding-ada-002' }
            ],
            object: 'list'
        };

        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue(mockResponse)
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: true,
            error: '',
            url: `https://${mockUrl}`,
            deployments: ['gpt-35-turbo', 'text-embedding-ada-002'],
            region: 'test-instance'
        });

        expect(mockFetch).toHaveBeenCalledWith(
            `https://${mockUrl}/openai/models?api-version=2024-02-01`,
            {
                method: 'GET',
                headers: {
                    'Api-Key': mockApiKey,
                    'Content-Type': 'application/json'
                }
            }
        );
    });

    test('should handle URL with https:// protocol', async () => {
        const urlWithProtocol = `https://${mockUrl}`;
        const mockResponse = {
            data: [],
            object: 'list'
        };

        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue(mockResponse)
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, urlWithProtocol);

        expect(result.valid).toBe(true);
        expect(result.url).toBe(urlWithProtocol);

        expect(mockFetch).toHaveBeenCalledWith(
            `${urlWithProtocol}/openai/models?api-version=2024-02-01`,
            expect.any(Object)
        );
    });

    test('should return invalid for 401 Unauthorized', async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 401,
            statusText: 'Unauthorized'
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: false,
            error: 'Invalid Azure OpenAI API key',
            url: `https://${mockUrl}`
        });
    });

    test('should return invalid for 403 Forbidden', async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 403,
            statusText: 'Forbidden'
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: false,
            error: 'API key exists but lacks required permissions',
            url: `https://${mockUrl}`
        });
    });

    test('should return invalid for 404 Not Found', async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 404,
            statusText: 'Not Found'
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: false,
            error: 'Azure OpenAI service not found at this URL',
            url: `https://${mockUrl}`
        });
    });

    test('should handle other HTTP error codes', async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            statusText: 'Internal Server Error'
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: false,
            error: 'HTTP 500: Internal Server Error',
            url: `https://${mockUrl}`
        });
    });

    test('should handle invalid response structure', async () => {
        const mockResponse = {
            // Missing 'object' field and no 'data' field
            error: 'Some API error'
        };

        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue(mockResponse)
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: false,
            error: 'Invalid response structure from Azure OpenAI API',
            url: `https://${mockUrl}`
        });
    });

    test('should handle network errors', async () => {
        const networkError = new Error('Network error');
        mockFetch.mockRejectedValueOnce(networkError);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: false,
            error: 'Network error'
        });
    });

    test('should handle DNS resolution errors', async () => {
        const dnsError = new Error('getaddrinfo ENOTFOUND nonexistent.openai.azure.com no such host');
        mockFetch.mockRejectedValueOnce(dnsError);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: false,
            error: 'Azure OpenAI service URL does not exist'
        });
    });

    test('should handle unknown errors', async () => {
        mockFetch.mockRejectedValueOnce('Unknown error');

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result).toEqual({
            valid: false,
            error: 'Unknown validation error'
        });
    });

    test('should extract region from URL correctly', async () => {
        const regionUrl = 'eastus-region.openai.azure.com';
        const mockResponse = {
            data: [],
            object: 'list'
        };

        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue(mockResponse)
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, regionUrl);

        expect(result.region).toBe('eastus-region');
    });

    test('should handle URL without region gracefully', async () => {
        const urlWithoutRegion = 'openai.azure.com';
        const mockResponse = {
            data: [],
            object: 'list'
        };

        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue(mockResponse)
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, urlWithoutRegion);

        expect(result.region).toBe('unknown');
    });

    test('should handle response with no deployments', async () => {
        const mockResponse = {
            object: 'list'
            // No 'data' field
        };

        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue(mockResponse)
        } as any);

        const result = await validateAzureOpenAICredentials(mockApiKey, mockUrl);

        expect(result.valid).toBe(true);
        expect(result.deployments).toEqual([]);
    });
});