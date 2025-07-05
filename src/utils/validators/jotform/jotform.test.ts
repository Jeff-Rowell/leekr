import { validateJotFormCredentials } from './jotform';

describe('validateJotFormCredentials', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.resetAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('should return valid when API responds with 200 status', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 200
        });

        const result = await validateJotFormCredentials('validApiKey123456789012345678901234');

        expect(result).toEqual({
            valid: true,
            error: ''
        });

        expect(fetch).toHaveBeenCalledWith(
            'https://api.jotform.com/user?apiKey=validApiKey123456789012345678901234',
            {
                method: 'GET',
                signal: expect.any(AbortSignal),
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'Leekr-Security-Scanner/1.0'
                }
            }
        );
    });

    test('should return valid when API responds with 299 status', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 299
        });

        const result = await validateJotFormCredentials('validApiKey123456789012345678901234');

        expect(result).toEqual({
            valid: true,
            error: ''
        });
    });

    test('should return invalid when API responds with 401 status', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 401
        });

        const result = await validateJotFormCredentials('invalidApiKey12345678901234567890123');

        expect(result).toEqual({
            valid: false,
            error: 'Invalid API key'
        });
    });

    test('should return invalid when API responds with 403 status', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 403
        });

        const result = await validateJotFormCredentials('forbiddenApiKey123456789012345678901');

        expect(result).toEqual({
            valid: false,
            error: 'Invalid API key'
        });
    });

    test('should return invalid when API responds with 500 status', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            status: 500
        });

        const result = await validateJotFormCredentials('serverErrorApiKey123456789012345678');

        expect(result).toEqual({
            valid: false,
            error: 'API returned status 500'
        });
    });

    test('should return invalid when request times out', async () => {
        global.fetch = jest.fn().mockImplementation(() => {
            return new Promise((resolve, reject) => {
                setTimeout(() => {
                    const error = new Error('Request timeout');
                    error.name = 'AbortError';
                    reject(error);
                }, 100);
            });
        });

        const result = await validateJotFormCredentials('timeoutApiKey123456789012345678901234');

        expect(result).toEqual({
            valid: false,
            error: 'Request timeout'
        });
    });

    test('should return invalid when fetch throws network error', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));

        const result = await validateJotFormCredentials('networkErrorApiKey12345678901234567890');

        expect(result).toEqual({
            valid: false,
            error: 'Network error'
        });
    });

    test('should return invalid when fetch throws unknown error', async () => {
        global.fetch = jest.fn().mockRejectedValue('Unknown error');

        const result = await validateJotFormCredentials('unknownErrorApiKey123456789012345678');

        expect(result).toEqual({
            valid: false,
            error: 'Unknown error occurred'
        });
    });

    test('should setup timeout for request', async () => {
        const mockSetTimeout = jest.spyOn(global, 'setTimeout');
        const mockClearTimeout = jest.spyOn(global, 'clearTimeout');
        
        global.fetch = jest.fn().mockResolvedValue({
            status: 200
        });

        await validateJotFormCredentials('testApiKey123456789012345678901234');

        expect(mockSetTimeout).toHaveBeenCalledWith(expect.any(Function), 10000);
        expect(mockClearTimeout).toHaveBeenCalled();

        mockSetTimeout.mockRestore();
        mockClearTimeout.mockRestore();
    });

    test('should handle AbortController properly when aborted', async () => {
        global.fetch = jest.fn().mockImplementation(() => {
            const abortError = new Error('Aborted');
            abortError.name = 'AbortError';
            return Promise.reject(abortError);
        });

        const result = await validateJotFormCredentials('testApiKey123456789012345678901234');

        expect(result).toEqual({
            valid: false,
            error: 'Request timeout'
        });
    });

    test('should trigger timeout and abort request when fetch takes too long', async () => {
        jest.useFakeTimers();
        
        let abortController: AbortController;
        global.fetch = jest.fn().mockImplementation((url, options) => {
            abortController = options.signal;
            return new Promise((resolve, reject) => {
                // Listen for abort signal
                options.signal.addEventListener('abort', () => {
                    const error = new Error('Request timeout');
                    error.name = 'AbortError';
                    reject(error);
                });
                // Simulate a slow request that never completes
            });
        });

        const promise = validateJotFormCredentials('testApiKey123456789012345678901234');
        
        // Fast-forward time to trigger the timeout
        jest.advanceTimersByTime(10000);
        
        const result = await promise;

        expect(result).toEqual({
            valid: false,
            error: 'Request timeout'
        });

        jest.useRealTimers();
    });

});