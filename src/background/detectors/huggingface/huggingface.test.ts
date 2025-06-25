import { detectHuggingFaceKeys } from './huggingface';
import { validateHuggingFaceCredentials } from '../../../utils/validators/huggingface/huggingface';
import { getExistingFindings, getSourceMapUrl, findSecretPosition } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

jest.mock('../../../utils/validators/huggingface/huggingface');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');

const mockValidateHuggingFaceCredentials = validateHuggingFaceCredentials as jest.MockedFunction<typeof validateHuggingFaceCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

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

    test('processes source map when available', async () => {
        const content = `const key="${mockApiKey}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 10 });

        // Mock fetch to return a simple successful response
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
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
        expect(global.fetch).toHaveBeenCalledWith(expect.any(String));
    });

    test('falls back to bundled content when source map processing fails', async () => {
        const content = `const key="${mockApiKey}";`;
        
        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/app.js.map'));
        
        // Mock fetch to fail
        (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

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

    test('processes source map with successful original position mapping', async () => {
        const content = `const key="${mockApiKey}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 5, column: 10 });

        // Mock successful source map processing
        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        mockConsumer.originalPositionFor.mockReturnValue({ line: 15, column: 5, source: 'original.js' });

        const mockSourceContent = 'line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\nline14\nline15 api key here\nline16\nline17\nline18\nline19\nline20\nline21\nline22\nline23\nline24\nline25\nline26\nline27\nline28\nline29\nline30';
        mockConsumer.sourceContentFor.mockReturnValue(mockSourceContent);

        // Mock SourceMapConsumer constructor
        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
        });

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('original.js');
        expect(result[0].sourceContent.contentStartLineNum).toBe(5); // 15 - 10
        expect(result[0].sourceContent.contentEndLineNum).toBe(25); // 15 + 10
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([14]); // line - 1
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });

    test('handles source map processing when findSecretPosition returns -1', async () => {
        const content = `const key="${mockApiKey}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: -1, column: -1 });

        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
        });

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js'); // Falls back to bundled content
        expect(mockFindSecretPosition).toHaveBeenCalledWith(content, mockApiKey);
        expect(mockConsumer.originalPositionFor).not.toHaveBeenCalled();
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });

    test('handles source map processing when originalPositionFor returns null source', async () => {
        const content = `const key="${mockApiKey}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 5, column: 10 });

        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        mockConsumer.originalPositionFor.mockReturnValue({ line: 15, column: 5, source: null });

        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
        });

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js'); // Falls back to bundled content
        expect(mockConsumer.sourceContentFor).not.toHaveBeenCalled();
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });

    test('handles source map processing when sourceContentFor returns null', async () => {
        const content = `const key="${mockApiKey}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 5, column: 10 });

        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        mockConsumer.originalPositionFor.mockReturnValue({ line: 15, column: 5, source: 'original.js' });
        mockConsumer.sourceContentFor.mockReturnValue(null);

        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
        });

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js'); // Falls back to bundled content
        expect(mockConsumer.sourceContentFor).toHaveBeenCalledWith('original.js');
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });

    test('handles source map processing when fetch response is not ok', async () => {
        const content = `const key="${mockApiKey}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));

        global.fetch = jest.fn().mockResolvedValue({
            ok: false,
            status: 404
        });

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js'); // Falls back to bundled content
        expect(global.fetch).toHaveBeenCalledWith(sourceMapUrl);
    });

    test('handles source map processing when originalPos.source has no filename', async () => {
        const content = `const key="${mockApiKey}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 5, column: 10 });

        // Mock successful source map processing but with empty source path
        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        mockConsumer.originalPositionFor.mockReturnValue({ line: 15, column: 5, source: '/' }); // Source path that results in empty pop()

        const mockSourceContent = 'line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\nline14\nline15 api key here\nline16\nline17\nline18\nline19\nline20\nline21\nline22\nline23\nline24\nline25\nline26\nline27\nline28\nline29\nline30';
        mockConsumer.sourceContentFor.mockReturnValue(mockSourceContent);

        // Mock SourceMapConsumer constructor
        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["/"],"mappings":""}')
        });

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        const result = await detectHuggingFaceKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe(''); // Empty filename when source path has no filename
        expect(result[0].sourceContent.contentStartLineNum).toBe(5); // 15 - 10
        expect(result[0].sourceContent.contentEndLineNum).toBe(25); // 15 + 10
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([14]); // line - 1
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });
});