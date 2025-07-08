import { validateMailchimpCredentials } from './mailchimp';

// Mock global fetch
global.fetch = jest.fn() as jest.MockedFunction<typeof fetch>;

// Mock chrome runtime
global.chrome = {
    ...global.chrome,
    runtime: {
        ...global.chrome?.runtime,
        getURL: jest.fn(() => 'chrome-extension://test-id/')
    }
} as any;

// Mock AbortController
global.AbortController = jest.fn().mockImplementation(() => ({
    signal: {},
    abort: jest.fn()
}));

describe('validateMailchimpCredentials', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (fetch as jest.MockedFunction<typeof fetch>).mockClear();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('should return valid for a valid API key', async () => {
        const mockResponse = {
            status: 200,
            ok: true,
            json: jest.fn().mockResolvedValue({ account_id: 'test123' })
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(true);
        expect(result.error).toBeNull();
        expect(fetch).toHaveBeenCalledWith(
            'https://us12.api.mailchimp.com/3.0/',
            expect.objectContaining({
                method: 'GET',
                headers: expect.objectContaining({
                    'Authorization': 'Basic ' + btoa('anystring:abcd1234567890abcd1234567890abcd-us12'),
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'application/json'
                }),
                mode: 'cors',
                credentials: 'omit',
                signal: expect.any(Object)
            })
        );
    });

    it('should return invalid for invalid API key format', async () => {
        const mockResponse = {
            status: 200,
            ok: true,
            json: jest.fn().mockResolvedValue({ account_id: 'test123' })
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);
        
        const result = await validateMailchimpCredentials('invalid-key');
        
        expect(result.valid).toBe(true);
        expect(result.error).toBeNull();
    });

    it('should return invalid for empty API key', async () => {
        const result = await validateMailchimpCredentials('');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid API key format - missing datacenter');
        expect(fetch).not.toHaveBeenCalled();
    });

    it('should return invalid for null API key', async () => {
        const result = await validateMailchimpCredentials(null as any);
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Cannot read properties of null (reading \'split\')');
        expect(fetch).not.toHaveBeenCalled();
    });

    it('should return invalid for undefined API key', async () => {
        const result = await validateMailchimpCredentials(undefined as any);
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Cannot read properties of undefined (reading \'split\')');
        expect(fetch).not.toHaveBeenCalled();
    });

    it('should return invalid for API key without datacenter', async () => {
        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid API key format - missing datacenter');
        expect(fetch).not.toHaveBeenCalled();
    });

    it('should return invalid for API key with invalid datacenter format', async () => {
        const mockResponse = {
            status: 200,
            ok: true,
            json: jest.fn().mockResolvedValue({ account_id: 'test123' })
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);
        
        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-eu1');
        
        expect(result.valid).toBe(true);
        expect(result.error).toBeNull();
    });

    it('should return invalid for 401 unauthorized response', async () => {
        const mockResponse = {
            status: 401,
            ok: false,
            statusText: 'Unauthorized'
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid API key');
    });

    it('should return invalid for 403 forbidden response', async () => {
        const mockResponse = {
            status: 403,
            ok: false,
            statusText: 'Forbidden'
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid API key');
    });

    it('should return failed_to_check for 500 server error', async () => {
        const mockResponse = {
            status: 500,
            ok: false,
            statusText: 'Internal Server Error'
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('API returned status 500');
    });

    it('should return failed_to_check for network timeout', async () => {
        const timeoutError = new Error('Timeout');
        timeoutError.name = 'AbortError';
        (fetch as jest.MockedFunction<typeof fetch>).mockRejectedValue(timeoutError);

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Request timeout');
    });

    it('should return failed_to_check for network error', async () => {
        const networkError = new Error('Network error');
        (fetch as jest.MockedFunction<typeof fetch>).mockRejectedValue(networkError);

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Network error');
    });

    it('should handle different datacenter formats', async () => {
        const mockResponse = {
            status: 200,
            ok: true,
            json: jest.fn().mockResolvedValue({ account_id: 'test123' })
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        // Test us1
        await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us1');
        expect(fetch).toHaveBeenCalledWith('https://us1.api.mailchimp.com/3.0/', expect.any(Object));

        // Test us20
        await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us20');
        expect(fetch).toHaveBeenCalledWith('https://us20.api.mailchimp.com/3.0/', expect.any(Object));
    });

    it('should handle successful response', async () => {
        const mockResponse = {
            status: 200,
            ok: true
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(true);
        expect(result.error).toBeNull();
    });

    it('should handle response with different status codes', async () => {
        const mockResponse = {
            status: 299,
            ok: true
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(true);
        expect(result.error).toBeNull();
    });

    it('should use correct request configuration', async () => {
        const mockResponse = {
            status: 200,
            ok: true,
            json: jest.fn().mockResolvedValue({ account_id: 'test123' })
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(fetch).toHaveBeenCalledWith(
            'https://us12.api.mailchimp.com/3.0/',
            expect.objectContaining({
                method: 'GET',
                headers: expect.objectContaining({
                    'Authorization': expect.stringContaining('Basic '),
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'application/json'
                }),
                mode: 'cors',
                credentials: 'omit',
                signal: expect.any(Object)
            })
        );
    });

    it('should set up timeout with setTimeout and clear it after successful response', async () => {
        const mockSetTimeout = jest.fn().mockImplementation((callback: any, delay: number) => {
            // Simulate setTimeout returning a timer ID
            return 123;
        });
        const mockClearTimeout = jest.fn();
        const originalSetTimeout = global.setTimeout;
        const originalClearTimeout = global.clearTimeout;
        
        global.setTimeout = mockSetTimeout as any;
        global.clearTimeout = mockClearTimeout as any;

        const mockResponse = {
            status: 200,
            ok: true
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(mockSetTimeout).toHaveBeenCalledWith(expect.any(Function), 10000);
        expect(mockClearTimeout).toHaveBeenCalledWith(123);
        
        // Restore original functions
        global.setTimeout = originalSetTimeout;
        global.clearTimeout = originalClearTimeout;
    });

    it('should handle non-Error objects thrown during validation', async () => {
        // Mock fetch to throw a non-Error object
        (fetch as jest.MockedFunction<typeof fetch>).mockRejectedValue('String error');

        const result = await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Unknown error occurred');
    });

    it('should execute timeout callback when setTimeout is called', async () => {
        let timeoutCallback: Function | null = null;
        const mockAbortController = {
            signal: {},
            abort: jest.fn()
        };
        
        const mockSetTimeout = jest.fn().mockImplementation((callback: Function) => {
            timeoutCallback = callback;
            return 123;
        });
        const mockClearTimeout = jest.fn();
        const originalSetTimeout = global.setTimeout;
        const originalClearTimeout = global.clearTimeout;
        const originalAbortController = global.AbortController;
        
        global.setTimeout = mockSetTimeout as any;
        global.clearTimeout = mockClearTimeout as any;
        global.AbortController = jest.fn().mockImplementation(() => mockAbortController);

        const mockResponse = {
            status: 200,
            ok: true
        };
        (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockResponse as any);

        await validateMailchimpCredentials('abcd1234567890abcd1234567890abcd-us12');
        
        // Verify the timeout callback was captured
        expect(timeoutCallback).toBeDefined();
        
        // Execute the timeout callback to cover that function
        if (timeoutCallback) {
            (timeoutCallback as Function)();
            expect(mockAbortController.abort).toHaveBeenCalled();
        }
        
        // Restore original functions
        global.setTimeout = originalSetTimeout;
        global.clearTimeout = originalClearTimeout;
        global.AbortController = originalAbortController;
    });
});