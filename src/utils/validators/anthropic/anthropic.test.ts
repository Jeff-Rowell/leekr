import { validateAnthropicCredentials } from './anthropic';

// Mock fetch globally
global.fetch = jest.fn();

describe('validateAnthropicCredentials', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('returns valid ADMIN type when admin endpoint returns 200', async () => {
        (global.fetch as jest.Mock).mockResolvedValueOnce({
            status: 200,
        });

        const result = await validateAnthropicCredentials('sk-ant-admin-key');

        expect(result).toEqual({
            valid: true,
            type: 'ADMIN',
            error: ''
        });

        expect(fetch).toHaveBeenCalledWith(
            'https://api.anthropic.com/v1/organizations/api_keys',
            {
                method: 'GET',
                headers: {
                    'x-api-key': 'sk-ant-admin-key',
                    'Content-Type': 'application/json',
                    'anthropic-version': '2023-06-01',
                },
            }
        );
    });

    test('returns valid USER type when admin endpoint fails but user endpoint returns 200', async () => {
        (global.fetch as jest.Mock)
            .mockResolvedValueOnce({ status: 401 }) // Admin endpoint fails
            .mockResolvedValueOnce({ status: 200 }); // User endpoint succeeds

        const result = await validateAnthropicCredentials('sk-ant-user-key');

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: ''
        });

        expect(fetch).toHaveBeenCalledTimes(2);
        expect(fetch).toHaveBeenNthCalledWith(2,
            'https://api.anthropic.com/v1/models',
            {
                method: 'GET',
                headers: {
                    'x-api-key': 'sk-ant-user-key',
                    'Content-Type': 'application/json',
                    'anthropic-version': '2023-06-01',
                },
            }
        );
    });

    test('returns valid admin type when both endpoints fail with 401/404', async () => {
        (global.fetch as jest.Mock)
            .mockResolvedValueOnce({ status: 401 }) // Admin endpoint fails
            .mockResolvedValueOnce({ status: 404 }); // User endpoint fails

        const result = await validateAnthropicCredentials('sk-ant-invalid-key');

        expect(result).toEqual({
            valid: true,
            type: 'admin',
            error: null
        });

        expect(fetch).toHaveBeenCalledTimes(2);
    });

    test('returns invalid when admin endpoint returns unexpected status', async () => {
        (global.fetch as jest.Mock).mockResolvedValueOnce({
            status: 500,
        });

        const result = await validateAnthropicCredentials('sk-ant-test-key');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unexpected HTTP status 500 from https://api.anthropic.com/v1/organizations/api_keys'
        });

        expect(fetch).toHaveBeenCalledTimes(1);
    });

    test('returns invalid when user endpoint returns unexpected status', async () => {
        (global.fetch as jest.Mock)
            .mockResolvedValueOnce({ status: 401 }) // Admin endpoint fails with 401
            .mockResolvedValueOnce({ status: 503 }); // User endpoint fails with unexpected status

        const result = await validateAnthropicCredentials('sk-ant-test-key');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unexpected HTTP status 503 from https://api.anthropic.com/v1/models'
        });

        expect(fetch).toHaveBeenCalledTimes(2);
    });

    test('handles AbortError exception', async () => {
        const abortError = new DOMException('Request was aborted', 'AbortError');
        (global.fetch as jest.Mock).mockRejectedValueOnce(abortError);

        const result = await validateAnthropicCredentials('sk-ant-test-key');

        expect(result).toEqual({
            valid: false,
            type: 'unkown', // Note: intentional typo in original code
            error: 'Request was aborted'
        });

        expect(fetch).toHaveBeenCalledTimes(1);
    });

    test('handles general network exception', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValueOnce(networkError);

        const result = await validateAnthropicCredentials('sk-ant-test-key');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: networkError
        });

        expect(fetch).toHaveBeenCalledTimes(1);
    });

    test('handles exception on user endpoint after admin endpoint succeeds with 401', async () => {
        const networkError = new Error('Network error on user endpoint');
        (global.fetch as jest.Mock)
            .mockResolvedValueOnce({ status: 404 }) // Admin endpoint fails with 404
            .mockRejectedValueOnce(networkError); // User endpoint throws

        const result = await validateAnthropicCredentials('sk-ant-test-key');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: networkError
        });

        expect(fetch).toHaveBeenCalledTimes(2);
    });
});