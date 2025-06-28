import { detectApolloKeys } from './apollo';
import { validateApolloCredentials } from '../../../utils/validators/apollo/apollo';
import { getExistingFindings, getSourceMapUrl, findSecretPosition } from '../../../utils/helpers/common';

// Mock dependencies
jest.mock('../../../utils/validators/apollo/apollo');
jest.mock('../../../utils/helpers/common', () => ({
    getExistingFindings: jest.fn(),
    getSourceMapUrl: jest.fn(),
    findSecretPosition: jest.fn().mockReturnValue({ line: 1, column: 0 }),
    storePatterns: jest.fn()
}));
jest.mock('../../../utils/helpers/computeFingerprint', () => ({
    computeFingerprint: jest.fn(() => Promise.resolve('test-fingerprint'))
}));
jest.mock('../../../utils/accuracy/entropy', () => ({
    calculateShannonEntropy: jest.fn(() => 5.0) // Mock high entropy to pass filter
}));
jest.mock('../../../utils/accuracy/falsePositives', () => ({
    isKnownFalsePositive: jest.fn(() => [false]) // Mock not a false positive
}));

jest.mock('../../../../external/source-map', () => ({
    SourceMapConsumer: {
        initialize: jest.fn(),
        with: jest.fn((content, options, callback) => {
            const mockConsumer = {
                originalPositionFor: jest.fn().mockReturnValue({
                    source: 'original.js',
                    line: 1,
                    column: 0
                }),
                sourceContentFor: jest.fn().mockReturnValue('const config = { apiKey: "secret" };')
            };
            callback(mockConsumer);
        })
    }
}));

// Mock chrome runtime
global.chrome = {
    runtime: {
        getURL: jest.fn().mockImplementation((path: string) => `chrome-extension://test/${path}`)
    }
} as any;

// Mock fetch for source maps
global.fetch = jest.fn();

const mockValidateApolloCredentials = validateApolloCredentials as jest.MockedFunction<typeof validateApolloCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

// Import mocked functions for entropy and false positive checks
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';
const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;
const mockIsKnownFalsePositive = isKnownFalsePositive as jest.MockedFunction<typeof isKnownFalsePositive>;

describe('detectApolloKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
    });

    const validApiKey = 'abcdefghij1234567890AB';
    const testUrl = 'https://example.com/app.js';

    test('should return empty array when no API keys found', async () => {
        const content = 'const config = { database: "postgresql://localhost" };';
        
        const result = await detectApolloKeys(content, testUrl);
        
        expect(result).toEqual([]);
        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
    });

    test('should detect valid Apollo API key', async () => {
        const content = `
            const config = {
                apiKey: "${validApiKey}",
                baseUrl: "https://api.apollo.io"
            };
        `;

        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            secretType: 'Apollo',
            secretValue: {
                match: {
                    api_key: validApiKey
                }
            },
            type: 'API Key',
            url: testUrl,
            fingerprint: 'test-fingerprint'
        });
    });

    test('should not return invalid API keys', async () => {
        const content = `
            const config = {
                apiKey: "${validApiKey}",
                baseUrl: "https://api.apollo.io"
            };
        `;

        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: false,
            error: 'Invalid Apollo API key'
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toEqual([]);
    });

    test('should handle multiple API keys and deduplicate', async () => {
        const content = `
            const config1 = { apiKey: "${validApiKey}" };
            const config2 = { key: "${validApiKey}" };
            const config3 = { Key: "xyztuvwxyz9876543210CD" };
        `;

        mockValidateApolloCredentials
            .mockResolvedValueOnce({ valid: true, error: '' })
            .mockResolvedValueOnce({ valid: false, error: 'Invalid key' });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledTimes(2);
        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(mockValidateApolloCredentials).toHaveBeenCalledWith('xyztuvwxyz9876543210CD');
        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.api_key).toBe(validApiKey);
    });

    test('should skip already found API keys', async () => {
        const content = `apiKey: "${validApiKey}"`;

        const existingFindings = [{
            secretType: 'Apollo',
            secretValue: {
                occurrence1: {
                    api_key: validApiKey
                }
            } as any,
            fingerprint: 'existing-fingerprint',
            validity: 'valid' as const,
            numOccurrences: 1,
            occurrences: new Set([])
        }];

        mockGetExistingFindings.mockResolvedValueOnce(existingFindings);

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should handle source map processing', async () => {
        const content = `config = { apiKey: "${validApiKey}" };\n//# sourceMappingURL=app.js.map`;

        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        // Mock getSourceMapUrl to return a URL
        mockGetSourceMapUrl.mockReturnValueOnce(new URL('https://example.com/app.js.map'));

        const mockSourceMapContent = JSON.stringify({
            version: 3,
            sources: ['original.js'],
            sourcesContent: ['const config = { apiKey: "secret" };'],
            mappings: 'AAAA'
        });

        mockFetch.mockResolvedValueOnce({
            text: () => Promise.resolve(mockSourceMapContent)
        } as Response);

        const result = await detectApolloKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].secretType).toBe('Apollo');
        // Verify that getSourceMapUrl was called
        expect(mockGetSourceMapUrl).toHaveBeenCalledWith(testUrl, content);
        // Verify that fetch was called for source map
        expect(mockFetch).toHaveBeenCalledWith('https://example.com/app.js.map');
        // Verify source map processing occurred
        expect(result[0].sourceContent.contentFilename).toBe('original.js');
        expect(result[0].sourceContent.content).toBe('const config = { apiKey: "secret" };');
    });

    test('should handle non-Apollo findings in existing findings', async () => {
        const content = `const config = { apiKey: "${validApiKey}" };`;

        const existingFindings = [{
            secretType: 'OpenAI',
            secretValue: {
                match: {
                    api_key: 'sk-someotherkey'
                }
            } as any,
            fingerprint: 'other-fingerprint',
            validity: 'valid' as const,
            numOccurrences: 1,
            occurrences: new Set([])
        }];

        mockGetExistingFindings.mockResolvedValueOnce(existingFindings);
        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1);
    });

    test('should handle content without source maps', async () => {
        const content = `const config = { apiKey: "${validApiKey}" };`;

        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js');
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([-1]);
    });

    test('should handle empty filename when URL has no path segments', async () => {
        const content = `const config = { apiKey: "${validApiKey}" };`;
        const emptyPathUrl = ''; // This will cause split('/').pop() to return undefined

        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, emptyPathUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe(''); // Should use the || "" fallback
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should filter out low entropy keys', async () => {
        const lowEntropyKey = 'aaaaaaaaaa1111111111aa'; // 22 chars but low entropy
        const content = `const key = "${lowEntropyKey}";`;

        // Mock low entropy for this specific key  
        mockCalculateShannonEntropy.mockReturnValueOnce(3.0); // Below 4.5 threshold

        const result = await detectApolloKeys(content, testUrl);

        // The pattern captures the full match, so we expect the key part to be extracted
        expect(mockCalculateShannonEntropy).toHaveBeenCalledWith(lowEntropyKey);
        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should filter out known false positives', async () => {
        const content = `const key = "${validApiKey}";`;

        // Mock as known false positive
        mockIsKnownFalsePositive.mockReturnValueOnce([true, 'test reason']);

        const result = await detectApolloKeys(content, testUrl);

        expect(mockIsKnownFalsePositive).toHaveBeenCalledWith(validApiKey);
        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should handle source map processing with valid key', async () => {
        const content = `const config = { apiKey: "${validApiKey}" };\n//# sourceMappingURL=app.js.map`;

        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        // Mock getSourceMapUrl to return a URL
        mockGetSourceMapUrl.mockReturnValueOnce(new URL('https://example.com/app.js.map'));

        const mockSourceMapContent = JSON.stringify({
            version: 3,
            sources: ['original.js'],
            sourcesContent: ['const config = { apiKey: "secret" };'],
            mappings: 'AAAA'
        });

        mockFetch.mockResolvedValueOnce({
            text: () => Promise.resolve(mockSourceMapContent)
        } as Response);

        const result = await detectApolloKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].secretType).toBe('Apollo');
        // Verify that getSourceMapUrl was called
        expect(mockGetSourceMapUrl).toHaveBeenCalledWith(testUrl, content);
        // Verify that fetch was called for source map
        expect(mockFetch).toHaveBeenCalledWith('https://example.com/app.js.map');
        // Verify source map processing occurred
        expect(result[0].sourceContent.contentFilename).toBe('original.js');
        expect(result[0].sourceContent.content).toBe('const config = { apiKey: "secret" };');
    });
});