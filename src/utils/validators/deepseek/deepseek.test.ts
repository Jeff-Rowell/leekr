import { validateDeepSeekApiKey } from './deepseek';

const originalFetch = global.fetch;

describe('validateDeepSeekApiKey', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        global.fetch = jest.fn();
    });

    afterAll(() => {
        global.fetch = originalFetch;
    });

    test('should return valid for successful API response', async () => {
        const mockResponse = {
            status: 200,
            json: async () => ({ is_available: true })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');

        expect(result.valid).toBe(true);
        expect(result.response).toEqual({ is_available: true });
        expect(result.error).toBeUndefined();
    });

    test('should return invalid for 401 status', async () => {
        const mockResponse = {
            status: 401
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateDeepSeekApiKey('sk-invalidkey1234567890abcd1234567');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid API key');
        expect(result.response).toBeUndefined();
    });

    test('should return invalid for unexpected status code', async () => {
        const mockResponse = {
            status: 500
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Unexpected status code: 500');
        expect(result.response).toBeUndefined();
    });

    test('should handle timeout error', async () => {
        const abortError = new Error('The operation was aborted.');
        abortError.name = 'AbortError';
        (global.fetch as jest.Mock).mockRejectedValue(abortError);

        const result = await validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Request timeout');
        expect(result.response).toBeUndefined();
    });

    test('should handle network error', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValue(networkError);

        const result = await validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Network error');
        expect(result.response).toBeUndefined();
    });

    test('should handle unknown error', async () => {
        (global.fetch as jest.Mock).mockRejectedValue('Unknown error');

        const result = await validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Unknown error occurred');
        expect(result.response).toBeUndefined();
    });

    test('should make correct API call', async () => {
        const mockResponse = {
            status: 200,
            json: async () => ({ is_available: true })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const apiKey = 'sk-abcd1234567890abcd1234567890abcd';
        await validateDeepSeekApiKey(apiKey);

        expect(global.fetch).toHaveBeenCalledWith(
            'https://api.deepseek.com/user/balance',
            expect.objectContaining({
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json; charset=utf-8',
                    'Authorization': `Bearer ${apiKey}`
                },
                signal: expect.any(AbortSignal)
            })
        );
    });

    test('should handle JSON parsing error', async () => {
        const mockResponse = {
            status: 200,
            json: async () => {
                throw new Error('Invalid JSON');
            }
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid JSON');
        expect(result.response).toBeUndefined();
    });

    test('should clear timeout on successful response', async () => {
        const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
        const mockResponse = {
            status: 200,
            json: async () => ({ is_available: true })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        await validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');

        expect(clearTimeoutSpy).toHaveBeenCalled();
        clearTimeoutSpy.mockRestore();
    });

    test('should clear timeout on error response', async () => {
        const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
        const mockResponse = {
            status: 401
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        await validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');

        expect(clearTimeoutSpy).toHaveBeenCalled();
        clearTimeoutSpy.mockRestore();
    });

    test('should trigger timeout callback', () => {
        jest.useFakeTimers();
        const abortSpy = jest.fn();
        
        // Mock AbortController
        const mockSignal = {};
        const mockController = {
            abort: abortSpy,
            signal: mockSignal
        };
        
        global.AbortController = jest.fn(() => mockController) as any;
        
        // Mock fetch to hang indefinitely
        (global.fetch as jest.Mock).mockImplementation(() => new Promise(() => {}));

        // Start the validation (don't await it)
        validateDeepSeekApiKey('sk-abcd1234567890abcd1234567890abcd');
        
        // Fast-forward time to trigger the timeout
        jest.advanceTimersByTime(10000);
        
        expect(abortSpy).toHaveBeenCalled();
        
        jest.useRealTimers();
    });
});