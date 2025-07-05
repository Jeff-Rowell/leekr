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
jest.mock('../../../utils/accuracy/programmingPatterns', () => ({
    isProgrammingPattern: jest.fn(() => false) // Mock not a programming pattern
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
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';
const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;
const mockIsKnownFalsePositive = isKnownFalsePositive as jest.MockedFunction<typeof isKnownFalsePositive>;
const mockIsProgrammingPattern = isProgrammingPattern as jest.MockedFunction<typeof isProgrammingPattern>;

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
        mockCalculateShannonEntropy.mockReturnValueOnce(3.0); // Below 3.9 threshold

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

    // New tests for contextual pattern matching
    test('should detect Apollo keys in variable assignments', async () => {
        const content = `
            const apolloKey = "${validApiKey}";
            const apollo_key = "${validApiKey}";
            const apollo_api_key = "${validApiKey}";
            let apolloToken = "${validApiKey}";
        `;

        mockValidateApolloCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1); // Should deduplicate the same key
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should detect Apollo keys in object properties', async () => {
        const content = `
            const config = {
                apolloKey: "${validApiKey}",
                apollo_key: "${validApiKey}",
                key: "${validApiKey}"
            };
        `;

        mockValidateApolloCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1); // Should deduplicate
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should detect Apollo keys in Apollo-specific contexts', async () => {
        const content = `
            Apollo.init({ key: "${validApiKey}" });
            apollo.config({ apiKey: "${validApiKey}" });
            new ApolloClient({ api_key: "${validApiKey}" });
        `;

        mockValidateApolloCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1); // Should deduplicate
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should detect Apollo keys in headers and auth contexts', async () => {
        const content = `
            headers: {
                'Authorization': "apollo ${validApiKey}",
                'x-apollo-key': "${validApiKey}",
                'apollo-key': "${validApiKey}"
            }
        `;

        mockValidateApolloCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1); // Should deduplicate
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should detect Apollo keys in environment variable patterns', async () => {
        const content = `
            const APOLLO_KEY = "${validApiKey}";
            process.env.APOLLO_API_KEY = "${validApiKey}";
            export const apollo_token = "${validApiKey}";
        `;

        mockValidateApolloCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1); // Should deduplicate
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should detect Apollo keys in general meaningful contexts with apollo/graphql reference', async () => {
        const content = `
            // Apollo GraphQL setup
            const apiKey = "${validApiKey}";
            
            // GraphQL apollo client
            const token = "${validApiKey}";
        `;

        mockValidateApolloCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1); // Should deduplicate
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should detect keys using fallback pattern in generic key contexts', async () => {
        const content = `
            // Generic key context should be caught by fallback
            const settings = {
                apiKey: "${validApiKey}",
                token: "${validApiKey}"
            };
        `;

        mockValidateApolloCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toHaveLength(1); // Should deduplicate
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should not detect programming-style false positives', async () => {
        const content = `
            // These look like programming identifiers, not API keys
            const ProvideAnomalyFeedback = "some value";
            const sqlInjectionHelper = "another value";
            const version2ApiHandler = "third value";
        `;

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should handle mixed contextual and fallback patterns', async () => {
        const apolloKey1 = 'abcdefghij1234567890AB';
        const apolloKey2 = 'xyztuvwxyz9876543210CD';
        
        const content = `
            // Contextual match
            const apolloApiKey = "${apolloKey1}";
            
            // Fallback pattern match (generic key context)
            const config = { key: "${apolloKey2}" };
        `;

        mockValidateApolloCredentials
            .mockResolvedValueOnce({ valid: true, error: '' })
            .mockResolvedValueOnce({ valid: true, error: '' });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledTimes(2);
        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(apolloKey1);
        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(apolloKey2);
        expect(result).toHaveLength(2);
    });

    test('should filter out PascalCase false positives', async () => {
        const content = `
            const ProvideAnomalyFeedback = "some value";
            const OptInPhoneNumberResult = "another value";
            const CustomerOwnedIpEnabled = "third value";
        `;

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should filter out camelCase false positives', async () => {
        const content = `
            const provideAnomalyFeedback = "some value";
            const optInPhoneNumberResult = "another value";
            const customerOwnedIpEnabled = "third value";
        `;

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should filter out patterns with consecutive capitals', async () => {
        const content = `
            const SqlInjectionMatchTuple = "some value";
            const HTTPResponseCodeError = "another value";
            const XMLParsingFailureMsg = "third value";
        `;

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should filter out patterns with numbers in programming style', async () => {
        const content = `
            const option1ResponseHandler = "some value";
            const error404NotFoundPage = "another value";
            const version2ApiEndpoint = "third value";
        `;

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should still detect valid random-looking 22-char strings', async () => {
        const randomKey = 'x7k9m2p4n8q1w6e3r5t0y9';
        const content = `const apiKey = "${randomKey}";`;

        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(randomKey);
        expect(result).toHaveLength(1);
        expect(result[0].secretType).toBe('Apollo');
    });

    test('should filter out programming patterns using centralized utility', async () => {
        // Test with 22-character strings that match programming patterns
        const programmingPattern = 'DisableSnapshotBlocking'; // 22 chars, PascalCase
        const content = `const config = { key: "${programmingPattern}" };`;

        // Mock programming pattern detection to return true
        mockIsProgrammingPattern.mockReturnValueOnce(true);

        const result = await detectApolloKeys(content, testUrl);

        expect(mockIsProgrammingPattern).toHaveBeenCalledWith(programmingPattern);
        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });

    test('should not filter out non-programming patterns', async () => {
        const nonProgrammingPattern = 'sk1234567890abcdef1234'; // 22 chars, looks like API key
        const content = `const config = { key: "${nonProgrammingPattern}" };`;

        // Mock programming pattern detection to return false
        mockIsProgrammingPattern.mockReturnValueOnce(false);
        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        const result = await detectApolloKeys(content, testUrl);

        expect(mockIsProgrammingPattern).toHaveBeenCalledWith(nonProgrammingPattern);
        expect(mockValidateApolloCredentials).toHaveBeenCalledWith(nonProgrammingPattern);
        expect(result).toHaveLength(1);
    });

    test('should filter out keys with incorrect length', async () => {
        const wrongLengthKey = 'abcdefghij1234567890A'; // 21 chars instead of 22
        const content = `const config = { key: "${wrongLengthKey}" };`;

        // Mock programming pattern detection to return false (not a programming pattern)
        mockIsProgrammingPattern.mockReturnValueOnce(false);

        const result = await detectApolloKeys(content, testUrl);

        expect(mockIsProgrammingPattern).toHaveBeenCalledWith(wrongLengthKey);
        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(result).toEqual([]);
    });
});