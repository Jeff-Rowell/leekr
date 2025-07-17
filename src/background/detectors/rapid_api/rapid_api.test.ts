import { detectRapidApiKeys } from './rapid_api';
import { validateRapidApiCredentials } from '../../../utils/validators/rapid_api/rapid_api';
import { getExistingFindings, findSecretPosition, getSourceMapUrl } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import * as sourceMap from '../../../../external/source-map';

jest.mock('../../../utils/validators/rapid_api/rapid_api');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map', () => ({
    SourceMapConsumer: {
        initialize: jest.fn(),
        with: jest.fn()
    }
}));

const mockValidateRapidApiCredentials = validateRapidApiCredentials as jest.MockedFunction<typeof validateRapidApiCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

global.fetch = jest.fn();
global.chrome = {
    runtime: {
        getURL: jest.fn().mockReturnValue('chrome-extension://test/libs/mappings.wasm')
    }
} as any;

describe('detectRapidApiKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        mockComputeFingerprint.mockResolvedValue('test-fingerprint');
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 0 });
        mockGetSourceMapUrl.mockReturnValue(null);
    });

    it('should return empty array when no matches found', async () => {
        const content = 'const config = { apiKey: "not-a-rapidapi-key" };';
        const url = 'https://example.com/test.js';

        const result = await detectRapidApiKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should detect valid rapidapi key', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toEqual({
            secretType: 'RapidAPI',
            fingerprint: 'test-fingerprint',
            secretValue: {
                match: {
                    api_key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
                }
            },
            filePath: 'test.js',
            url: 'https://example.com/test.js',
            type: 'API Key',
            sourceContent: {
                content: JSON.stringify({
                    api_key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
                }),
                contentFilename: 'test.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            },
            validity: 'valid'
        });

        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith(
            'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
        );
    });

    it('should skip invalid rapidapi keys', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: false,
            type: 'API_KEY',
            error: 'Invalid key'
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith(
            'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
        );
    });

    it('should handle duplicate keys', async () => {
        const content = `
            const apiKey1 = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";
            const apiKey2 = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";
        `;
        const url = 'https://example.com/test.js';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(mockValidateRapidApiCredentials).toHaveBeenCalledTimes(1);
    });

    it('should skip already found keys', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';

        mockGetExistingFindings.mockResolvedValue([
            {
                fingerprint: 'existing-fingerprint',
                secretType: 'RapidAPI',
                numOccurrences: 1,
                validity: 'valid',
                discoveredAt: '2023-01-01T00:00:00Z',
                occurrences: new Set(),
                secretValue: {
                    '0': {
                        api_key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
                    }
                }
            }
        ]);

        const result = await detectRapidApiKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
    });

    it('should handle multiple different keys', async () => {
        const content = `
            const apiKey1 = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";
            const apiKey2 = "zyxwvutsrq0987654321ZYXWVUTSRQ0987654321098765432B";
        `;
        const url = 'https://example.com/test.js';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(2);
        expect(mockValidateRapidApiCredentials).toHaveBeenCalledTimes(2);
    });

    it('should handle source map processing', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';
        const sourceMapUrl = 'https://example.com/test.js.map';
        const sourceMapContent = '{"version":3,"sources":["original.js"],"mappings":"AAAA"}';
        const originalSource = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';

        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 20 });

        const mockResponse = {
            text: jest.fn().mockResolvedValue(sourceMapContent)
        };
        (fetch as jest.Mock).mockImplementation((url) => {
            if (typeof url === 'string' || url instanceof URL) {
                return Promise.resolve(mockResponse);
            }
            return Promise.reject(new Error('Invalid URL'));
        });

        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: 'original.js',
                line: 1,
                column: 20
            }),
            sourceContentFor: jest.fn().mockReturnValue(originalSource)
        };

        (sourceMap.SourceMapConsumer.with as jest.Mock).mockImplementation((content, options, callback) => {
            callback(mockConsumer);
        });

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toEqual({
            content: originalSource,
            contentFilename: 'original.js',
            contentStartLineNum: -4,
            contentEndLineNum: 6,
            exactMatchNumbers: [1]
        });

        expect(sourceMap.SourceMapConsumer.initialize).toHaveBeenCalledWith({
            'lib/mappings.wasm': 'chrome-extension://test/libs/mappings.wasm'
        });
    });

    it('should handle source map processing with null source', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';
        const sourceMapUrl = 'https://example.com/test.js.map';
        const sourceMapContent = '{"version":3,"sources":["original.js"],"mappings":"AAAA"}';

        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 20 });

        const mockResponse = {
            text: jest.fn().mockResolvedValue(sourceMapContent)
        };
        (fetch as jest.Mock).mockImplementation((url) => {
            if (typeof url === 'string' || url instanceof URL) {
                return Promise.resolve(mockResponse);
            }
            return Promise.reject(new Error('Invalid URL'));
        });

        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: null,
                line: 1,
                column: 20
            }),
            sourceContentFor: jest.fn().mockReturnValue(null)
        };

        (sourceMap.SourceMapConsumer.with as jest.Mock).mockImplementation((content, options, callback) => {
            callback(mockConsumer);
        });

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toEqual({
            content: JSON.stringify({
                api_key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
            }),
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle URLs without filename', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].filePath).toBe('');
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    it('should handle empty URLs', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = '';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].filePath).toBe('');
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    it('should handle URLs that split to empty array', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const originalSplit = String.prototype.split;
        String.prototype.split = jest.fn().mockReturnValue([]);
        
        const url = 'test-url';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].filePath).toBe('');
        expect(result[0].sourceContent.contentFilename).toBe('');
        
        String.prototype.split = originalSplit;
    });

    it('should handle regex pattern matching correctly', async () => {
        const testCases = [
            { key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A', shouldMatch: true },
            { key: 'ABCDEFGHIJ1234567890abcdefghij1234567890123456789B', shouldMatch: true },
            { key: '1234567890abcdefghijABCDEFGHIJ1234567890123456789C', shouldMatch: true },
            { key: 'short', shouldMatch: false },
            { key: 'abcdefghij1234567890ABCDEFGHIJ123456789012345678901', shouldMatch: false },
            { key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789AB', shouldMatch: false }
        ];

        for (const testCase of testCases) {
            const content = `const apiKey = "${testCase.key}";`;
            const url = 'https://example.com/test.js';

            mockValidateRapidApiCredentials.mockResolvedValue({
                valid: true,
                type: 'API_KEY',
                error: null
            });

            const result = await detectRapidApiKeys(content, url);

            if (testCase.shouldMatch) {
                expect(result).toHaveLength(1);
                expect((result[0] as any).secretValue.match.api_key).toBe(testCase.key);
            } else {
                expect(result).toHaveLength(0);
            }
        }
    });

    it('should filter out keys with low entropy', async () => {
        const content = 'const apiKey = "fwd-header-x-amz-server-side-encryption-customer-";';
        const url = 'https://example.com/test.js';

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(0);
        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
    });

    it('should filter out keys with entropy below threshold', async () => {
        // Create a 50-character key with low entropy (mostly repeated characters)
        const lowEntropyKey = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb';
        const content = `const apiKey = "${lowEntropyKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(0);
        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
    });

    it('should filter out programming patterns', async () => {
        const content = 'const apiKey = "NotifyUpdateProvisionedProductEngineWorkflowResult";';
        const url = 'https://example.com/test.js';

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(0);
        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
    });

    it('should filter out camelCase programming patterns', async () => {
        const content = 'const apiKey = "getApplicationConfigurationProviderServiceManager";';
        const url = 'https://example.com/test.js';

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(0);
        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
    });

    it('should test multiple false positive filtering cases', async () => {
        const falsePositives = [
            'amz-fwd-header-x-amz-server-side-encryption-bucket',
            'configurateApplicationServiceManagerHelperUtility',
            'createNotificationServiceHandlerFactoryBuilder'
        ];

        for (const falsePositive of falsePositives) {
            const content = `const key = "${falsePositive}";`;
            const url = 'https://example.com/test.js';

            const result = await detectRapidApiKeys(content, url);

            expect(result).toHaveLength(0);
        }

        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
    });

    it('should not filter valid keys with sufficient entropy', async () => {
        const validKeys = [
            '1234567890ABCDEFGHIJklmnopqrstuvwxyz1234567890ABcd',
            'aBcDeFgHiJ1234567890KlMnOpQrSt0987654321UvWxYzXyZw'
        ];

        for (const validKey of validKeys) {
            const content = `const key = "${validKey}";`;
            const url = 'https://example.com/test.js';

            mockValidateRapidApiCredentials.mockResolvedValue({
                valid: true,
                type: 'API_KEY',
                error: null
            });

            const result = await detectRapidApiKeys(content, url);

            expect(result).toHaveLength(1);
            expect(mockValidateRapidApiCredentials).toHaveBeenCalled();
            
            jest.clearAllMocks();
        }
    });

    it('should return empty array when all keys are filtered by entropy/programming patterns', async () => {
        const content = `
            const lowEntropyKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            const programmingKey = "configurateApplicationServiceManagerHelperUtility";
        `;
        const url = 'https://example.com/test.js';

        const result = await detectRapidApiKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
    });

    it('should return empty array when validKeys is empty after filtering', async () => {
        const content = 'const key = "amz-fwd-header-x-amz-server-side-encryption-bucket";';
        const url = 'https://example.com/test.js';

        const result = await detectRapidApiKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
    });

    it('should return empty array when all keys fail validation', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: false,
            type: 'API_KEY',
            error: 'Invalid key'
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith(
            'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
        );
    });

    it('should handle sourceMap with no original source', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';
        const sourceMapUrl = 'https://example.com/test.js.map';
        const sourceMapContent = '{"version":3,"sources":["original.js"],"mappings":"AAAA"}';

        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 20 });

        const mockResponse = {
            text: jest.fn().mockResolvedValue(sourceMapContent)
        };
        (fetch as jest.Mock).mockImplementation((url) => {
            if (typeof url === 'string' || url instanceof URL) {
                return Promise.resolve(mockResponse);
            }
            return Promise.reject(new Error('Invalid URL'));
        });

        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: null,
                line: 1,
                column: 20
            }),
            sourceContentFor: jest.fn().mockReturnValue(null)
        };

        (sourceMap.SourceMapConsumer.with as jest.Mock).mockImplementation((content, options, callback) => {
            callback(mockConsumer);
        });

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toEqual({
            content: JSON.stringify({
                api_key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
            }),
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle mixed valid and invalid keys', async () => {
        const content = `
            const validKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";
            const invalidKey = "zyxwvutsrq0987654321ZYXWVUTSRQ0987654321098765432B";
        `;
        const url = 'https://example.com/test.js';

        mockValidateRapidApiCredentials
            .mockResolvedValueOnce({
                valid: true,
                type: 'API_KEY',
                error: null
            })
            .mockResolvedValueOnce({
                valid: false,
                type: 'API_KEY',
                error: 'Invalid key'
            });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect((result[0] as any).secretValue.match.api_key).toBe('abcdefghij1234567890ABCDEFGHIJ1234567890123456789A');
        expect(mockValidateRapidApiCredentials).toHaveBeenCalledTimes(2);
    });

    it('should handle empty validOccurrences at the end', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Some error'
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith(
            'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
        );
    });

    it('should handle var declaration for newSourceContent', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";';
        const url = 'https://example.com/test.js';

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        const result = await detectRapidApiKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.content).toBe(JSON.stringify({
            api_key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789A'
        }));
    });
});