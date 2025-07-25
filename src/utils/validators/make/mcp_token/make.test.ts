import { validateMakeMcpToken } from './make';

global.fetch = jest.fn();

describe('validateMakeMcpToken', () => {
    const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

    beforeEach(() => {
        mockFetch.mockClear();
    });

    describe('successful validation', () => {
        it('should return valid true when API returns 200', async () => {
            mockFetch.mockResolvedValue({
                status: 200,
            } as Response);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(mockFetch).toHaveBeenCalledWith(
                'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse',
                {
                    method: 'GET',
                    headers: {
                        'Accept': 'text/event-stream',
                        'Cache-Control': 'no-cache'
                    }
                }
            );
            expect(result).toEqual({ valid: true });
        });
    });

    describe('failed validation', () => {
        it('should return valid false when API returns 401', async () => {
            mockFetch.mockResolvedValue({
                status: 401,
            } as Response);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when API returns 403', async () => {
            mockFetch.mockResolvedValue({
                status: 403,
            } as Response);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when API returns 404', async () => {
            mockFetch.mockResolvedValue({
                status: 404,
            } as Response);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when API returns 500', async () => {
            mockFetch.mockResolvedValue({
                status: 500,
            } as Response);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when API returns 502', async () => {
            mockFetch.mockResolvedValue({
                status: 502,
            } as Response);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when API returns other status codes', async () => {
            mockFetch.mockResolvedValue({
                status: 418,
            } as Response);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({ valid: false });
        });
    });

    describe('error handling', () => {
        it('should handle fetch network errors', async () => {
            const networkError = new Error('Network error');
            mockFetch.mockRejectedValue(networkError);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({
                valid: false,
                error: 'Network error'
            });
        });

        it('should handle TypeError', async () => {
            const typeError = new TypeError('Type error');
            mockFetch.mockRejectedValue(typeError);

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({
                valid: false,
                error: 'Type error'
            });
        });

        it('should handle unknown errors', async () => {
            mockFetch.mockRejectedValue('Unknown error');

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({
                valid: false,
                error: 'Unknown error'
            });
        });

        it('should handle non-Error objects', async () => {
            mockFetch.mockRejectedValue({ message: 'Custom error' });

            const result = await validateMakeMcpToken('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');

            expect(result).toEqual({
                valid: false,
                error: '[object Object]'
            });
        });
    });

    describe('edge cases', () => {
        it('should handle empty string URL', async () => {
            const typeError = new TypeError('Failed to fetch');
            mockFetch.mockRejectedValue(typeError);

            const result = await validateMakeMcpToken('');

            expect(result).toEqual({
                valid: false,
                error: 'Failed to fetch'
            });
        });

        it('should handle malformed URL', async () => {
            const typeError = new TypeError('Invalid URL');
            mockFetch.mockRejectedValue(typeError);

            const result = await validateMakeMcpToken('not-a-valid-url');

            expect(result).toEqual({
                valid: false,
                error: 'Invalid URL'
            });
        });
    });
});