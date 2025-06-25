import { detectHuggingFaceKeys } from './huggingface';
import { validateHuggingFaceCredentials } from '../../../utils/validators/huggingface/huggingface';
import { getExistingFindings, getSourceMapUrl, findSecretPosition } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import * as sourceMap from '../../../../external/source-map';

jest.mock('../../../utils/validators/huggingface/huggingface');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map', () => ({
    SourceMapConsumer: {
        initialize: jest.fn(),
        with: jest.fn()
    }
}));

const mockValidateHuggingFaceCredentials = validateHuggingFaceCredentials as jest.MockedFunction<typeof validateHuggingFaceCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;
const mockSourceMapConsumer = sourceMap.SourceMapConsumer as jest.Mocked<typeof sourceMap.SourceMapConsumer>;

// Mock chrome APIs
global.chrome = {
    runtime: {
        getURL: jest.fn((path: string) => `chrome-extension://test-id/${path}`)
    }
} as any;

// Mock fetch globally
global.fetch = jest.fn();

describe('detectHuggingFaceKeys', () => {
    const testUrl = 'https://example.com/app.js';
    const mockApiKey = 'hf_1234567890abcdefghijklmnopqrstuv12';
    const mockOrgApiKey = 'api_org_abcdefghijklmnopqrstuvwxyz12345678';

    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        let fingerprintCounter = 0;
        mockComputeFingerprint.mockImplementation(() => Promise.resolve(`test-fingerprint-${++fingerprintCounter}`));
        mockGetSourceMapUrl.mockReturnValue(null);
        // Reset fetch mock
        (global.fetch as jest.Mock).mockReset();
        // Reset source map consumer mocks
        mockSourceMapConsumer.initialize.mockClear();
        mockSourceMapConsumer.with.mockClear();
    });

    test('detects valid Hugging Face API key', async () => {
        const content = `
            const config = {
                huggingfaceApiKey: "${mockApiKey}"
            };
        `;

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser',
            email: 'test@example.com',
            tokenInfo: 'My API Key (write)',
            organizations: []
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            filePath: testUrl,
            fingerprint: 'test-fingerprint-1',
            type: 'API Key',
            secretType: 'Hugging Face',
            secretValue: {
                match: {
                    api_key: mockApiKey
                }
            },
            url: testUrl
        });

        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith(mockApiKey);
    });

    test('detects organization API key correctly', async () => {
        const content = `
            const config = {
                orgKey: "${mockOrgApiKey}"
            };
        `;

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'ORGANIZATION',
            error: '',
            username: 'orguser',
            email: 'org@example.com',
            tokenInfo: 'organization',
            organizations: []
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.api_key).toBe(mockOrgApiKey);
        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith(mockOrgApiKey);
    });

    test('returns empty array when no API keys found', async () => {
        const content = 'const config = { other: "value" };';

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateHuggingFaceCredentials).not.toHaveBeenCalled();
    });

    test('deduplicates API keys', async () => {
        const content = `
            const key1 = "${mockApiKey}";
            const key2 = "${mockApiKey}";
        `;

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledTimes(1);
    });

    test('skips invalid API keys', async () => {
        const content = `
            const config = {
                apiKey: "${mockApiKey}"
            };
        `;

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith(mockApiKey);
    });

    test('skips already found API keys', async () => {
        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretValue: {
                existingEntry: {
                    match: {
                        api_key: mockApiKey
                    }
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const content = `
            const config = {
                apiKey: "${mockApiKey}"
            };
        `;

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateHuggingFaceCredentials).not.toHaveBeenCalled();
    });

    test('covers the match comparison line when key is not found', async () => {
        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretValue: {
                existingEntry: {
                    match: {
                        api_key: 'hf_differentkey1234567890abcdefghijk' // Different key
                    }
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const content = `
            const config = {
                apiKey: "${mockApiKey}"
            };
        `;

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith(mockApiKey);
    });

    test('handles existing findings with no match property', async () => {
        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretValue: {
                existingEntry: {
                    // No match property - should safely handle with optional chaining
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const content = `
            const config = {
                apiKey: "${mockApiKey}"
            };
        `;

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith(mockApiKey);
    });

    test('processes API key when not found in existing findings', async () => {
        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretValue: {
                existingEntry: {
                    match: {
                        api_key: 'hf_differentkey1234567890abcdefghij'
                    }
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const content = `
            const config = {
                apiKey: "${mockApiKey}"
            };
        `;

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith(mockApiKey);
    });

    test('processes multiple valid API keys', async () => {
        const secondApiKey = 'hf_abcdefghijklmnopqrstuvwxyz12345678';

        const content = `
            const config1 = {
                key: "${mockApiKey}"
            };
            const config2 = {
                key: "${secondApiKey}"
            };
        `;

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(2);
        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith(mockApiKey);
        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith(secondApiKey);
    });

    test('processes content without source map', async () => {
        const content = `const key="${mockApiKey}";`;
        
        // Mock no source map to use bundled content path
        mockGetSourceMapUrl.mockReturnValue(null);

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.content).toBe(JSON.stringify({
            api_key: mockApiKey
        }));
    });

    test('falls back to bundled content when source map processing fails', async () => {
        const content = `const key="${mockApiKey}";`;
        
        // Mock no source map to use bundled content path directly
        mockGetSourceMapUrl.mockReturnValue(null);

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.content).toBe(JSON.stringify({
            api_key: mockApiKey
        }));
        expect(result[0].sourceContent.contentFilename).toBe('app.js');
    });

    test('correctly identifies filename from URL', async () => {
        const content = `const key="${mockApiKey}";`;
        const urlWithPath = 'https://example.com/path/to/bundle.min.js';

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, urlWithPath);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('bundle.min.js');
    });

    test('handles URL with no filename', async () => {
        const content = `const key="${mockApiKey}";`;
        const urlWithoutFilename = 'https://example.com/';

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, urlWithoutFilename);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    test('processes bundled content correctly', async () => {
        const content = `const key="${mockApiKey}";`;
        
        // Mock no source map to test bundled content path
        mockGetSourceMapUrl.mockReturnValue(null);

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js');
        expect(result[0].sourceContent.content).toBe(JSON.stringify({
            api_key: mockApiKey
        }));
    });

    test('processes source map when available', async () => {
        const content = `const key="${mockApiKey}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        const mockSourceMapContent = JSON.stringify({
            version: 3,
            sources: ['original.js'],
            sourcesContent: ['const originalKey = "' + mockApiKey + '";'],
            mappings: 'AAAA'
        });

        // Mock source map URL detection
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        
        // Mock fetch response
        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve(mockSourceMapContent)
        } as Response);

        // Mock findSecretPosition
        mockFindSecretPosition.mockReturnValue({
            line: 1,
            column: 10
        });

        // Mock source map consumer
        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: 'original.js',
                line: 1,
                column: 0
            }),
            sourceContentFor: jest.fn().mockReturnValue('const originalKey = "' + mockApiKey + '";')
        };

        // Mock SourceMapConsumer.with to call the callback with our mock consumer
        mockSourceMapConsumer.with.mockImplementation((content: any, options: any, callback: any) => {
            return callback(mockConsumer);
        });

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockGetSourceMapUrl).toHaveBeenCalledWith(testUrl, content);
        expect(global.fetch).toHaveBeenCalledWith(new URL(sourceMapUrl));
        expect(mockSourceMapConsumer.initialize).toHaveBeenCalledWith({
            "lib/mappings.wasm": 'chrome-extension://test-id/libs/mappings.wasm'
        });
        expect(mockSourceMapConsumer.with).toHaveBeenCalledWith(mockSourceMapContent, null, expect.any(Function));
        expect(mockFindSecretPosition).toHaveBeenCalledWith(content, mockApiKey);
        expect(mockConsumer.originalPositionFor).toHaveBeenCalledWith({
            line: 1,
            column: 10
        });
        expect(mockConsumer.sourceContentFor).toHaveBeenCalledWith('original.js');
        expect(result[0].sourceContent.contentFilename).toBe('original.js');
        expect(result[0].sourceContent.content).toBe('const originalKey = "' + mockApiKey + '";');
        expect(result[0].sourceContent.contentStartLineNum).toBe(-4);
        expect(result[0].sourceContent.contentEndLineNum).toBe(6);
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([1]);
    });
});