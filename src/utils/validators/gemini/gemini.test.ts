import { validateGeminiCredentials } from './gemini';
import { GeminiValidationResult } from '../../../types/gemini';

// Mock fetch globally
global.fetch = jest.fn();

// Mock crypto.subtle for Web Crypto API (optional, fallback will be used if not available)

describe('validateGeminiCredentials', () => {
    const mockApiKey = 'account-1234567890ABCDEFGH12';
    const mockApiSecret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ12';
    const mockMasterKey = 'master-1234567890ABCDEFGH12';

    beforeEach(() => {
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('returns valid result with account data when API credentials are valid', async () => {
        const mockResponse = {
            account: 'account123',
            name: 'Test Account',
            is_active: true,
            trade_volume_30d: 1000000,
            created: 1640995200 // 2022-01-01
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result).toEqual({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'account123',
            name: 'Test Account',
            isMainAccount: false,
            isActive: true,
            tradeVolume: 1000000,
            accountCreated: '2022-01-01T00:00:00.000Z'
        });

        expect(global.fetch).toHaveBeenCalledWith('https://api.gemini.com/v1/account', {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain',
                'Content-Length': '0',
                'X-GEMINI-APIKEY': mockApiKey,
                'X-GEMINI-PAYLOAD': expect.any(String),
                'X-GEMINI-SIGNATURE': expect.any(String),
                'Cache-Control': 'no-cache'
            }
        });
    });

    test('returns valid result for master key with primary account param', async () => {
        const mockResponse = {
            account: 'primary',
            name: 'Master Account',
            is_active: true,
            trade_volume_30d: 5000000,
            created: 1640995200
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateGeminiCredentials(mockMasterKey, mockApiSecret);

        expect(result).toEqual({
            valid: true,
            type: 'MASTER',
            error: '',
            account: 'primary',
            name: 'Master Account',
            isMainAccount: true,
            isActive: true,
            tradeVolume: 5000000,
            accountCreated: '2022-01-01T00:00:00.000Z'
        });
    });

    test('returns valid result when optional fields are missing', async () => {
        const mockResponse = {
            account: 'account456',
            name: 'Minimal Account'
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result).toEqual({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'account456',
            name: 'Minimal Account',
            isMainAccount: false,
            isActive: undefined,
            tradeVolume: undefined,
            accountCreated: undefined
        });
    });

    test('returns invalid result when API credentials are unauthorized (401)', async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
            status: 401
        });

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key or secret',
        });
    });

    test('returns invalid result when API credentials are forbidden (403)', async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
            status: 403
        });

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key or secret',
        });
    });

    test('returns invalid result for unexpected HTTP status codes', async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
            status: 429
        });

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unexpected HTTP response status 429',
        });
    });

    test('handles network errors gracefully', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValue(networkError);

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Network error',
        });
    });

    test('handles non-Error exceptions', async () => {
        (global.fetch as jest.Mock).mockRejectedValue('String error');

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unknown error occurred',
        });
    });

    test('handles JSON parsing errors', async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.reject(new Error('Invalid JSON'))
        });

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Invalid JSON',
        });
    });

    test('handles crypto signature creation gracefully', async () => {
        // Test that the function works with the fallback implementation
        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve({
                account: 'test-account',
                name: 'Test Account',
                is_active: true
            })
        });

        const result = await validateGeminiCredentials(mockApiKey, mockApiSecret);

        expect(result.valid).toBe(true);
        expect(result.type).toBe('ACCOUNT');
    });

    test('uses Web Crypto API in browser environment', async () => {
        // Save original crypto to restore later
        const originalCrypto = global.crypto;
        
        // Mock actual ArrayBuffer signature result to trigger the conversion lines
        const mockSignature = new ArrayBuffer(48); // 48 bytes for SHA-384
        const uint8View = new Uint8Array(mockSignature);
        // Fill with test data that will create a predictable hex string
        for (let i = 0; i < 48; i++) {
            uint8View[i] = i % 16; // Values 0-15 for predictable hex
        }

        const mockImportKey = jest.fn().mockResolvedValue({});
        const mockSign = jest.fn().mockResolvedValue(mockSignature);

        // Completely replace global crypto to ensure our mock is used
        delete (global as any).crypto;
        global.crypto = {
            subtle: {
                importKey: mockImportKey,
                sign: mockSign
            }
        } as any;

        global.TextEncoder = jest.fn().mockImplementation(() => ({
            encode: jest.fn().mockReturnValue(new Uint8Array([1, 2, 3]))
        }));

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve({
                account: 'test-account',
                name: 'Test Account',
                is_active: true,
                trade_volume_30d: 1000,
                created: 1640995200
            })
        });

        const result = await validateGeminiCredentials(
            'account-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );

        expect(result).toEqual({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account',
            name: 'Test Account',
            isMainAccount: false,
            isActive: true,
            tradeVolume: 1000,
            accountCreated: '2022-01-01T00:00:00.000Z'
        });

        // Verify the Web Crypto API methods were called
        expect(mockImportKey).toHaveBeenCalled();
        expect(mockSign).toHaveBeenCalled();
        
        // Restore original crypto
        global.crypto = originalCrypto;
    });

    test('uses Node.js fallback when Web Crypto API is not available', async () => {
        // Remove Web Crypto API
        const originalCrypto = global.crypto;
        delete (global as any).crypto;

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve({
                account: 'test-account',
                name: 'Test Account',
                is_active: true,
                trade_volume_30d: 1000,
                created: 1640995200
            })
        });

        const result = await validateGeminiCredentials(
            'master-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );

        expect(result).toEqual({
            valid: true,
            type: 'MASTER',
            error: '',
            account: 'test-account',
            name: 'Test Account',
            isMainAccount: true,
            isActive: true,
            tradeVolume: 1000,
            accountCreated: '2022-01-01T00:00:00.000Z'
        });

        // Restore original crypto
        global.crypto = originalCrypto;
    });

    test('handles Web Crypto API errors', async () => {
        // Mock Web Crypto API with error
        const originalCrypto = global.crypto;
        global.crypto = {
            subtle: {
                importKey: jest.fn().mockRejectedValue(new Error('Crypto API error')),
                sign: jest.fn()
            }
        } as any;

        global.TextEncoder = jest.fn().mockImplementation(() => ({
            encode: jest.fn().mockReturnValue(new Uint8Array([1, 2, 3]))
        }));

        const result = await validateGeminiCredentials(
            'account-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Crypto API error'
        });

        // Restore original crypto
        global.crypto = originalCrypto;
    });

    test('handles undefined crypto with subtle property', async () => {
        // Mock crypto object without subtle
        const originalCrypto = global.crypto;
        global.crypto = {} as any;

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve({
                account: 'test-account',
                name: 'Test Account',
                is_active: false
            })
        });

        const result = await validateGeminiCredentials(
            'account-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );

        expect(result).toEqual({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account',
            name: 'Test Account',
            isMainAccount: false,
            isActive: false,
            tradeVolume: undefined,
            accountCreated: undefined
        });

        // Restore original crypto
        global.crypto = originalCrypto;
    });

    test('handles crypto sign method error', async () => {
        // Mock Web Crypto API with sign error
        const originalCrypto = global.crypto;
        const mockCryptoKey = {};
        global.crypto = {
            subtle: {
                importKey: jest.fn().mockResolvedValue(mockCryptoKey),
                sign: jest.fn().mockRejectedValue(new Error('Sign operation failed'))
            }
        } as any;

        global.TextEncoder = jest.fn().mockImplementation(() => ({
            encode: jest.fn().mockReturnValue(new Uint8Array([1, 2, 3]))
        }));

        const result = await validateGeminiCredentials(
            'account-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Sign operation failed'
        });

        // Restore original crypto
        global.crypto = originalCrypto;
    });
});