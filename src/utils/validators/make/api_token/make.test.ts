import { validateMakeApiToken } from './make';

global.fetch = jest.fn();

describe('validateMakeApiToken', () => {
    const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

    beforeEach(() => {
        mockFetch.mockClear();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('successful validation', () => {
        it('should return valid true when API returns 200 with array data', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue(['scope1', 'scope2'])
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('bbb49d50-239a-4609-9569-63ea15ef0997');

            expect(mockFetch).toHaveBeenCalledWith(
                'https://eu1.make.com/api/v2/users/me/current-authorization',
                {
                    method: 'GET',
                    headers: {
                        'Authorization': 'Token bbb49d50-239a-4609-9569-63ea15ef0997',
                        'Content-Type': 'application/json'
                    }
                }
            );
            expect(result).toEqual({ valid: true });
            expect(mockResponse.json).toHaveBeenCalled();
        });

        it('should return valid true when API returns 200 with empty array', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue([])
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('924ee925-f461-466a-99bc-63cfce078057');

            expect(result).toEqual({ valid: true });
        });
    });

    describe('failed validation', () => {
        it('should return valid false when API returns 401', async () => {
            const mockResponse = {
                status: 401
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('invalid-token');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when API returns 403', async () => {
            const mockResponse = {
                status: 403
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('f71ec344-95f2-4a8c-bda7-3f76f7a6eeea');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when API returns 404', async () => {
            const mockResponse = {
                status: 404
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('nonexistent-token');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when API returns 500', async () => {
            const mockResponse = {
                status: 500
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('server-error-token');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when response data is not an array', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue({ error: 'Invalid token' })
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('invalid-format-token');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when response data is null', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue(null)
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('null-response-token');

            expect(result).toEqual({ valid: false });
        });

        it('should return valid false when response data is undefined', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue(undefined)
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('undefined-response-token');

            expect(result).toEqual({ valid: false });
        });
    });

    describe('error handling', () => {
        it('should handle fetch network errors', async () => {
            const networkError = new Error('Network error');
            mockFetch.mockRejectedValue(networkError);

            const result = await validateMakeApiToken('network-error-token');

            expect(result).toEqual({
                valid: false,
                error: 'Network error'
            });
        });

        it('should handle JSON parsing errors', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockRejectedValue(new Error('Invalid JSON'))
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('json-error-token');

            expect(result).toEqual({
                valid: false
            });
        });

        it('should handle JSON parsing errors with non-Error objects', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockRejectedValue('string error')
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('json-error-token');

            expect(result).toEqual({
                valid: false
            });
        });

        it('should handle unknown errors', async () => {
            mockFetch.mockRejectedValue('Unknown error');

            const result = await validateMakeApiToken('unknown-error-token');

            expect(result).toEqual({
                valid: false,
                error: 'Unknown error occurred'
            });
        });

        it('should handle TypeError', async () => {
            const typeError = new TypeError('Type error occurred');
            mockFetch.mockRejectedValue(typeError);

            const result = await validateMakeApiToken('type-error-token');

            expect(result).toEqual({
                valid: false,
                error: 'Type error occurred'
            });
        });
    });

    describe('edge cases', () => {
        it('should handle empty string token', async () => {
            const mockResponse = {
                status: 401
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('');

            expect(mockFetch).toHaveBeenCalledWith(
                'https://eu1.make.com/api/v2/users/me/current-authorization',
                {
                    method: 'GET',
                    headers: {
                        'Authorization': 'Token ',
                        'Content-Type': 'application/json'
                    }
                }
            );
            expect(result).toEqual({ valid: false });
        });

        it('should handle token with special characters', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue(['scope'])
            };
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validateMakeApiToken('token-with-special-chars!@#');

            expect(mockFetch).toHaveBeenCalledWith(
                'https://eu1.make.com/api/v2/users/me/current-authorization',
                {
                    method: 'GET',
                    headers: {
                        'Authorization': 'Token token-with-special-chars!@#',
                        'Content-Type': 'application/json'
                    }
                }
            );
            expect(result).toEqual({ valid: true });
        });
    });
});