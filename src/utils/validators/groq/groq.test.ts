import { validateGroqCredentials } from './groq';

describe('validateGroqCredentials', () => {
    beforeEach(() => {
        global.fetch = jest.fn();
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('should return valid true for successful API response', async () => {
        const mockResponse = {
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue({ data: [] })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateGroqCredentials('gsk_' + 'a'.repeat(52));

        expect(result).toEqual({
            valid: true,
            error: ''
        });
        expect(global.fetch).toHaveBeenCalledWith(
            'https://api.groq.com/openai/v1/models',
            expect.objectContaining({
                method: 'GET',
                headers: expect.objectContaining({
                    'Authorization': 'Bearer gsk_' + 'a'.repeat(52)
                }),
                signal: expect.any(Object)
            })
        );
    });

    it('should return valid false for 401 unauthorized response', async () => {
        const mockResponse = {
            ok: false,
            status: 401,
            json: jest.fn().mockResolvedValue({ error: 'Unauthorized' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateGroqCredentials('gsk_invalid_key_test');

        expect(result).toEqual({
            valid: false,
            error: 'Invalid API key'
        });
    });

    it('should return valid false for 403 forbidden response', async () => {
        const mockResponse = {
            ok: false,
            status: 403,
            json: jest.fn().mockResolvedValue({ error: 'Forbidden' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateGroqCredentials('gsk_forbidden_key_test');

        expect(result).toEqual({
            valid: false,
            error: 'Invalid API key'
        });
    });

    it('should return error for other HTTP error responses', async () => {
        const mockResponse = {
            ok: false,
            status: 500,
            json: jest.fn().mockResolvedValue({ error: 'Internal Server Error' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateGroqCredentials('gsk_server_error_test');

        expect(result).toEqual({
            valid: false,
            error: 'API returned status 500'
        });
    });

    it('should return error for network errors', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValue(networkError);

        const result = await validateGroqCredentials('gsk_network_error_test');

        expect(result).toEqual({
            valid: false,
            error: 'Network error'
        });
    });

    it('should return error for timeout', async () => {
        const timeoutError = new Error('The operation was aborted');
        timeoutError.name = 'AbortError';
        (global.fetch as jest.Mock).mockRejectedValue(timeoutError);

        const result = await validateGroqCredentials('gsk_timeout_test_key');

        expect(result).toEqual({
            valid: false,
            error: 'Request timeout'
        });
    });

    it('should abort request after 10 seconds', async () => {
        jest.useFakeTimers();
        
        const mockAbortController = {
            signal: { aborted: false },
            abort: jest.fn()
        };
        global.AbortController = jest.fn(() => mockAbortController as any);
        
        const fetchPromise = new Promise(() => {});
        (global.fetch as jest.Mock).mockReturnValue(fetchPromise);

        const validationPromise = validateGroqCredentials('gsk_timeout_test_key');
        
        jest.advanceTimersByTime(10000);
        
        expect(mockAbortController.abort).toHaveBeenCalled();
        
        jest.useRealTimers();
    });

    it('should return error for non-Error thrown objects', async () => {
        // Mock fetch to throw a non-Error object (like a string)
        (global.fetch as jest.Mock).mockImplementation(() => {
            throw 'String error'; // Throwing a string instead of Error object
        });

        const result = await validateGroqCredentials('gsk_test_key_that_causes_non_error_throw');

        expect(result).toEqual({
            valid: false,
            error: 'Unknown error occurred'
        });
    });
});