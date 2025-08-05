import { validatePayPalOAuthCredentials } from './paypal_oauth';

global.fetch = jest.fn();
const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

describe('PayPal OAuth Validator', () => {
    beforeEach(() => {
        mockFetch.mockClear();
    });

    afterEach(() => {
        jest.resetAllMocks();
    });

    describe('validatePayPalOAuthCredentials', () => {
        it('should return valid true when API call succeeds', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue({
                    scope: 'test-scope',
                    access_token: 'test-token',
                    token_type: 'Bearer',
                    app_id: 'test-app-id',
                    expires_in: 3600,
                    nonce: 'test-nonce'
                })
            };
            
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validatePayPalOAuthCredentials('test-client-id', 'test-client-secret');

            expect(result.valid).toBe(true);
            expect(result.error).toBeUndefined();
            expect(mockFetch).toHaveBeenCalledWith(
                'https://api-m.sandbox.paypal.com/v1/oauth2/token',
                {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Accept-Language': 'en_US',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': `Basic ${btoa('test-client-id:test-client-secret')}`
                    },
                    body: 'grant_type=client_credentials'
                }
            );
        });

        it('should return valid false when API call returns 400', async () => {
            const mockResponse = {
                status: 400,
                json: jest.fn().mockResolvedValue({
                    error: 'invalid_client',
                    error_description: 'Client authentication failed'
                })
            };
            
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validatePayPalOAuthCredentials('invalid-client-id', 'invalid-client-secret');

            expect(result.valid).toBe(false);
            expect(result.error).toBe('Client authentication failed');
        });

        it('should return valid false when API call returns 401', async () => {
            const mockResponse = {
                status: 401,
                json: jest.fn().mockResolvedValue({
                    error: 'unauthorized',
                    error_description: 'Unauthorized'
                })
            };
            
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validatePayPalOAuthCredentials('unauthorized-client-id', 'unauthorized-client-secret');

            expect(result.valid).toBe(false);
            expect(result.error).toBe('Unauthorized');
        });

        it('should return valid false when API call returns 500', async () => {
            const mockResponse = {
                status: 500,
                json: jest.fn().mockResolvedValue({
                    error: 'server_error',
                    error_description: 'Internal server error'
                })
            };
            
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validatePayPalOAuthCredentials('client-id', 'client-secret');

            expect(result.valid).toBe(false);
            expect(result.error).toBe('Internal server error');
        });

        it('should handle error response without error_description', async () => {
            const mockResponse = {
                status: 400,
                json: jest.fn().mockResolvedValue({
                    error: 'invalid_request'
                })
            };
            
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validatePayPalOAuthCredentials('client-id', 'client-secret');

            expect(result.valid).toBe(false);
            expect(result.error).toBe('invalid_request');
        });

        it('should return valid false when fetch throws an error', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'));

            const result = await validatePayPalOAuthCredentials('client-id', 'client-secret');

            expect(result.valid).toBe(false);
            expect(result.error).toBe('Network error');
        });

        it('should return valid false when fetch throws a non-Error object', async () => {
            mockFetch.mockRejectedValue('String error');

            const result = await validatePayPalOAuthCredentials('client-id', 'client-secret');

            expect(result.valid).toBe(false);
            expect(result.error).toBe('Unknown error occurred');
        });

        it('should handle 201 status code as valid', async () => {
            const mockResponse = {
                status: 201,
                json: jest.fn().mockResolvedValue({
                    scope: 'test-scope',
                    access_token: 'test-token',
                    token_type: 'Bearer',
                    app_id: 'test-app-id',
                    expires_in: 3600,
                    nonce: 'test-nonce'
                })
            };
            
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validatePayPalOAuthCredentials('test-client-id', 'test-client-secret');

            expect(result.valid).toBe(true);
            expect(result.error).toBeUndefined();
        });

        it('should handle 299 status code as valid', async () => {
            const mockResponse = {
                status: 299,
                json: jest.fn().mockResolvedValue({
                    scope: 'test-scope',
                    access_token: 'test-token',
                    token_type: 'Bearer',
                    app_id: 'test-app-id',
                    expires_in: 3600,
                    nonce: 'test-nonce'
                })
            };
            
            mockFetch.mockResolvedValue(mockResponse as any);

            const result = await validatePayPalOAuthCredentials('test-client-id', 'test-client-secret');

            expect(result.valid).toBe(true);
            expect(result.error).toBeUndefined();
        });
    });
});