import { validateOpenAICredentials } from './openai';
import { OpenAIValidationResult } from '../../../types/openai';

// Mock fetch globally
global.fetch = jest.fn();

describe('validateOpenAICredentials', () => {
    const mockApiKey = 'sk-test123T3BlbkFJtest456';

    beforeEach(() => {
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('returns valid result with user data when API key is valid', async () => {
        const mockResponse = {
            id: 'user-123',
            orgs: {
                data: [
                    {
                        description: 'Test Organization',
                        personal: false,
                        is_default: true
                    }
                ]
            },
            mfa_flag_enabled: true,
            created: 1640995200 // 2022-01-01
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            id: 'user-123',
            totalOrgs: 1,
            mfaEnabled: true,
            createdAt: '2022-01-01T00:00:00.000Z',
            description: 'Test Organization',
            isPersonal: false,
            isDefault: true
        });

        expect(global.fetch).toHaveBeenCalledWith('https://api.openai.com/v1/me', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Authorization': `Bearer ${mockApiKey}`,
            },
        });
    });

    test('returns valid result without organization data when orgs array is empty', async () => {
        const mockResponse = {
            id: 'user-456',
            orgs: {
                data: []
            },
            mfa_flag_enabled: false,
            created: 1640995200
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            id: 'user-456',
            totalOrgs: 0,
            mfaEnabled: false,
            createdAt: '2022-01-01T00:00:00.000Z',
            description: undefined,
            isPersonal: undefined,
            isDefault: undefined
        });
    });

    test('returns valid result when orgs is undefined', async () => {
        const mockResponse = {
            id: 'user-789',
            mfa_flag_enabled: true,
            created: 1640995200
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            id: 'user-789',
            totalOrgs: 0,
            mfaEnabled: true,
            createdAt: '2022-01-01T00:00:00.000Z',
            description: undefined,
            isPersonal: undefined,
            isDefault: undefined
        });
    });

    test('returns valid result when created timestamp is undefined', async () => {
        const mockResponse = {
            id: 'user-abc',
            orgs: {
                data: []
            },
            mfa_flag_enabled: false
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            id: 'user-abc',
            totalOrgs: 0,
            mfaEnabled: false,
            createdAt: undefined,
            description: undefined,
            isPersonal: undefined,
            isDefault: undefined
        });
    });

    test('returns invalid result when API key is unauthorized (401)', async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
            status: 401
        });

        const result = await validateOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key',
        });
    });

    test('returns invalid result for unexpected HTTP status codes', async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
            status: 429
        });

        const result = await validateOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unexpected HTTP response status 429',
        });
    });

    test('handles network errors gracefully', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValue(networkError);

        const result = await validateOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Network error',
        });
    });

    test('handles non-Error exceptions', async () => {
        (global.fetch as jest.Mock).mockRejectedValue('String error');

        const result = await validateOpenAICredentials(mockApiKey);

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

        const result = await validateOpenAICredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Invalid JSON',
        });
    });
});