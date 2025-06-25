import { validateHuggingFaceCredentials } from './huggingface';
import { HuggingFaceValidationResult } from '../../../types/huggingface';

// Mock fetch globally
global.fetch = jest.fn();

describe('validateHuggingFaceCredentials', () => {
    const mockApiKey = 'hf_1234567890abcdefghijklmnopqrstuv12';

    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('returns valid result with user token data when API key is valid', async () => {
        const mockResponse = {
            name: 'testuser',
            email: 'test@example.com',
            orgs: [
                { name: 'testorg', roleInOrg: 'member' },
                { name: 'mycompany', roleInOrg: 'admin' }
            ],
            auth: {
                accessToken: {
                    displayName: 'My API Key',
                    role: 'write'
                }
            }
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateHuggingFaceCredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser',
            email: 'test@example.com',
            tokenInfo: 'My API Key (write)',
            organizations: ['testorg:member', 'mycompany:admin']
        });

        expect(global.fetch).toHaveBeenCalledWith('https://huggingface.co/api/whoami-v2', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${mockApiKey}`,
                'Content-Type': 'application/json'
            }
        });
    });

    test('returns valid result with organization token data when API key is valid', async () => {
        const mockResponse = {
            name: 'orguser',
            email: 'org@example.com',
            orgs: [],
            auth: {
                type: 'organization'
            }
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateHuggingFaceCredentials('api_org_1234567890abcdefghijklmnopqrstuv12');

        expect(result).toEqual({
            valid: true,
            type: 'ORGANIZATION',
            error: '',
            username: 'orguser',
            email: 'org@example.com',
            tokenInfo: 'organization',
            organizations: []
        });
    });

    test('returns valid result with unknown token type when auth info is missing', async () => {
        const mockResponse = {
            name: 'unknownuser',
            email: 'unknown@example.com',
            orgs: [],
            auth: {}
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateHuggingFaceCredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            username: 'unknownuser',
            email: 'unknown@example.com',
            tokenInfo: 'Unknown Token Type',
            organizations: []
        });
    });

    test('returns valid result when only displayName is present', async () => {
        const mockResponse = {
            name: 'testuser',
            email: 'test@example.com',
            orgs: [],
            auth: {
                accessToken: {
                    displayName: 'My API Key'
                }
            }
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateHuggingFaceCredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser',
            email: 'test@example.com',
            tokenInfo: 'My API Key',
            organizations: []
        });
    });

    test('returns valid result when only role is present', async () => {
        const mockResponse = {
            name: 'testuser',
            email: 'test@example.com',
            orgs: [],
            auth: {
                accessToken: {
                    role: 'read'
                }
            }
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateHuggingFaceCredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser',
            email: 'test@example.com',
            tokenInfo: '(read)',
            organizations: []
        });
    });

    test('returns valid result when orgs is undefined', async () => {
        const mockResponse = {
            name: 'testuser',
            email: 'test@example.com',
            auth: {
                accessToken: {
                    displayName: 'My API Key',
                    role: 'write'
                }
            }
        };

        (global.fetch as jest.Mock).mockResolvedValue({
            status: 200,
            json: () => Promise.resolve(mockResponse)
        });

        const result = await validateHuggingFaceCredentials(mockApiKey);

        expect(result).toEqual({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser',
            email: 'test@example.com',
            tokenInfo: 'My API Key (write)',
            organizations: []
        });
    });

    test('returns invalid result when API key is unauthorized (401)', async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
            status: 401
        });

        const result = await validateHuggingFaceCredentials(mockApiKey);

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

        const result = await validateHuggingFaceCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unexpected HTTP response status 429',
        });
    });

    test('handles network errors gracefully', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValue(networkError);

        const result = await validateHuggingFaceCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Network error',
        });
    });

    test('handles non-Error exceptions', async () => {
        (global.fetch as jest.Mock).mockRejectedValue('String error');

        const result = await validateHuggingFaceCredentials(mockApiKey);

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

        const result = await validateHuggingFaceCredentials(mockApiKey);

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Invalid JSON',
        });
    });
});