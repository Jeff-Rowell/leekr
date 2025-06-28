import { validateApolloCredentials } from './apollo';
import { ApolloValidationResult } from '../../../types/apollo';

// Mock fetch
global.fetch = jest.fn();
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

describe('validateApolloCredentials', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    const mockApiKey = 'abcdefghij1234567890AB';

    test('should validate successfully with correct API key', async () => {
        mockFetch.mockResolvedValueOnce({
            status: 200,
            json: () => Promise.resolve({ is_logged_in: true })
        } as Response);

        const result = await validateApolloCredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            error: ''
        });
        expect(mockFetch).toHaveBeenCalledWith(
            'https://api.apollo.io/v1/auth/health',
            {
                method: 'GET',
                headers: {
                    'x-api-key': mockApiKey
                }
            }
        );
    });

    test('should return invalid for 304 response', async () => {
        mockFetch.mockResolvedValueOnce({
            status: 304,
            statusText: 'Not Modified'
        } as Response);

        const result = await validateApolloCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            error: 'Invalid Apollo API key'
        });
    });

    test('should return invalid when is_logged_in is false', async () => {
        mockFetch.mockResolvedValueOnce({
            status: 200,
            json: () => Promise.resolve({ is_logged_in: false })
        } as Response);

        const result = await validateApolloCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            error: 'Apollo API key validation failed'
        });
    });

    test('should return invalid when is_logged_in is missing', async () => {
        mockFetch.mockResolvedValueOnce({
            status: 200,
            json: () => Promise.resolve({ other_field: 'value' })
        } as Response);

        const result = await validateApolloCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            error: 'Apollo API key validation failed'
        });
    });

    test('should handle other HTTP status codes', async () => {
        mockFetch.mockResolvedValueOnce({
            status: 500,
            statusText: 'Internal Server Error'
        } as Response);

        const result = await validateApolloCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            error: 'HTTP 500: Internal Server Error'
        });
    });

    test('should handle JSON parsing errors', async () => {
        mockFetch.mockResolvedValueOnce({
            status: 200,
            json: () => Promise.reject(new Error('Invalid JSON'))
        } as Response);

        const result = await validateApolloCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            error: 'Invalid JSON'
        });
    });

    test('should handle network errors', async () => {
        const networkError = new Error('Network error');
        mockFetch.mockRejectedValueOnce(networkError);

        const result = await validateApolloCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            error: 'Network error'
        });
    });

    test('should handle unknown errors', async () => {
        mockFetch.mockRejectedValueOnce('Unknown error');

        const result = await validateApolloCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            error: 'Unknown validation error'
        });
    });
});