import { validateMailgunCredentials } from './mailgun';

describe('validateMailgunCredentials', () => {
    beforeEach(() => {
        global.fetch = jest.fn();
        global.btoa = jest.fn();
        global.Request = jest.fn().mockImplementation((url, options) => ({
            url,
            ...options,
            headers: {
                set: jest.fn(),
                ...options?.headers
            }
        }));
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('should return valid true for successful API response', async () => {
        const mockResponse = {
            status: 200,
            json: jest.fn().mockResolvedValue({ total_count: 1, items: [] })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);
        (global.btoa as jest.Mock).mockReturnValue('YXBpOnRlc3Rfa2V5');

        const result = await validateMailgunCredentials('test_key');

        expect(result).toEqual({
            valid: true,
            error: ''
        });
        expect(global.fetch).toHaveBeenCalled();
    });

    it('should handle 72-character API key with different auth method', async () => {
        const mockResponse = {
            status: 200,
            json: jest.fn().mockResolvedValue({ total_count: 1, items: [] })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

        const longApiKey = 'a'.repeat(72);
        const result = await validateMailgunCredentials(longApiKey);

        expect(result).toEqual({
            valid: true,
            error: ''
        });
        expect(global.fetch).toHaveBeenCalled();
    });

    it('should return valid false for 401 unauthorized response', async () => {
        const mockResponse = {
            status: 401,
            json: jest.fn().mockResolvedValue({ message: 'Forbidden' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);
        (global.btoa as jest.Mock).mockReturnValue('YXBpOmludmFsaWRfa2V5');

        const result = await validateMailgunCredentials('invalid_key');

        expect(result).toEqual({
            valid: false,
            error: 'Invalid API key'
        });
    });

    it('should return valid false for 403 forbidden response', async () => {
        const mockResponse = {
            status: 403,
            json: jest.fn().mockResolvedValue({ message: 'Forbidden' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);
        (global.btoa as jest.Mock).mockReturnValue('YXBpOmZvcmJpZGRlbl9rZXk=');

        const result = await validateMailgunCredentials('forbidden_key');

        expect(result).toEqual({
            valid: false,
            error: 'Invalid API key'
        });
    });

    it('should return error for other HTTP error responses', async () => {
        const mockResponse = {
            status: 500,
            json: jest.fn().mockResolvedValue({ message: 'Internal Server Error' })
        };
        (global.fetch as jest.Mock).mockResolvedValue(mockResponse);
        (global.btoa as jest.Mock).mockReturnValue('YXBpOmVycm9yX2tleQ==');

        const result = await validateMailgunCredentials('error_key');

        expect(result).toEqual({
            valid: false,
            error: 'API returned status 500'
        });
    });

    it('should return error for network errors', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValue(networkError);
        (global.btoa as jest.Mock).mockReturnValue('YXBpOm5ldHdvcmtfZXJyb3I=');

        const result = await validateMailgunCredentials('network_error');

        expect(result).toEqual({
            valid: false,
            error: 'Network error'
        });
    });

    it('should return error for timeout', async () => {
        const timeoutError = new Error('The operation was aborted');
        timeoutError.name = 'AbortError';
        (global.fetch as jest.Mock).mockRejectedValue(timeoutError);
        (global.btoa as jest.Mock).mockReturnValue('YXBpOnRpbWVvdXRfdGVzdA==');

        const result = await validateMailgunCredentials('timeout_test');

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
        (global.btoa as jest.Mock).mockReturnValue('YXBpOnRpbWVvdXRfdGVzdA==');

        const validationPromise = validateMailgunCredentials('timeout_test');
        
        jest.advanceTimersByTime(10000);
        
        expect(mockAbortController.abort).toHaveBeenCalled();
        
        jest.useRealTimers();
    });

    it('should return error for non-Error thrown objects', async () => {
        (global.fetch as jest.Mock).mockImplementation(() => {
            throw 'String error';
        });
        (global.btoa as jest.Mock).mockReturnValue('YXBpOnN0cmluZ19lcnJvcg==');

        const result = await validateMailgunCredentials('string_error');

        expect(result).toEqual({
            valid: false,
            error: 'Unknown error occurred'
        });
    });
});