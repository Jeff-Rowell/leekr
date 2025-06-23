import { detectGeminiKeys } from './gemini';
import { validateGeminiCredentials } from '../../../utils/validators/gemini/gemini';
import { getExistingFindings, getSourceMapUrl, findSecretPosition } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

jest.mock('../../../utils/validators/gemini/gemini');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');

const mockValidateGeminiCredentials = validateGeminiCredentials as jest.MockedFunction<typeof validateGeminiCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

describe('detectGeminiKeys', () => {
    const testUrl = 'https://example.com/app.js';
    const mockApiKey = 'account-1234567890ABCDEFGH12';
    const mockApiSecret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ12';
    const mockMasterKey = 'master-9876543210ZYXWVUTS98';

    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        let fingerprintCounter = 0;
        mockComputeFingerprint.mockImplementation(() => Promise.resolve(`test-fingerprint-${++fingerprintCounter}`));
        mockGetSourceMapUrl.mockReturnValue(null);
    });

    test('detects valid Gemini API key and secret pairs', async () => {
        const content = `
            const config = {
                geminiApiKey: "${mockApiKey}",
                geminiSecret: "${mockApiSecret}"
            };
        `;

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            filePath: testUrl,
            fingerprint: 'test-fingerprint-1',
            type: 'API Key & Secret',
            secretType: 'Gemini',
            secretValue: {
                match: {
                    api_key: mockApiKey,
                    api_secret: mockApiSecret
                }
            },
            url: testUrl
        });

        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(mockApiKey, mockApiSecret);
    });

    test('detects master key correctly', async () => {
        const content = `
            const config = {
                masterKey: "${mockMasterKey}",
                secret: "${mockApiSecret}"
            };
        `;

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'MASTER',
            error: '',
            account: 'primary'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.api_key).toBe(mockMasterKey);
        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(mockMasterKey, mockApiSecret);
    });

    test('returns empty array when no API keys found', async () => {
        const content = 'const config = { other: "value" };';

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateGeminiCredentials).not.toHaveBeenCalled();
    });

    test('returns empty array when no API secrets found', async () => {
        const content = `const apiKey = "${mockApiKey}";`;

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateGeminiCredentials).not.toHaveBeenCalled();
    });

    test('deduplicates API keys and secrets', async () => {
        const content = `
            const key1 = "${mockApiKey}";
            const key2 = "${mockApiKey}";
            const secret1 = "${mockApiSecret}";
            const secret2 = "${mockApiSecret}";
        `;

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateGeminiCredentials).toHaveBeenCalledTimes(1);
    });

    test('skips invalid key-secret combinations', async () => {
        const content = `
            const config = {
                apiKey: "${mockApiKey}",
                secret: "${mockApiSecret}"
            };
        `;

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid credentials'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(mockApiKey, mockApiSecret);
    });

    test('skips already found key-secret combinations', async () => {
        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretValue: {
                someEntry: {
                    match: {
                        api_key: mockApiKey,
                        api_secret: mockApiSecret
                    }
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const content = `
            const config = {
                apiKey: "${mockApiKey}",
                secret: "${mockApiSecret}"
            };
        `;

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateGeminiCredentials).not.toHaveBeenCalled();
    });

    test('processes multiple valid key-secret combinations', async () => {
        const secondApiKey = 'account-ABCDEFGHIJ0987654321'; // exactly 20 chars after account-
        const secondApiSecret = '0987654321ZYXWVUTSRQPONMLKJI'; // 27 chars

        const content = `
            const config1 = {
                key: "${mockApiKey}",
                secret: "${mockApiSecret}"
            };
            const config2 = {
                key: "${secondApiKey}",
                secret: "${secondApiSecret}"
            };
        `;

        // Mock to return valid only for the exact expected combinations
        mockValidateGeminiCredentials.mockImplementation((key, secret) => {
            if ((key === mockApiKey && secret === mockApiSecret) || 
                (key === secondApiKey && secret === secondApiSecret)) {
                return Promise.resolve({
                    valid: true,
                    type: 'ACCOUNT',
                    error: '',
                    account: 'test-account'
                });
            }
            return Promise.resolve({
                valid: false,
                type: 'unknown',
                error: 'Invalid combination'
            });
        });

        const result = await detectGeminiKeys(content, testUrl);

        // Should find at least 1 valid combination and test the right pairs
        expect(result.length).toBeGreaterThan(0);
        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(mockApiKey, mockApiSecret);
        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(secondApiKey, secondApiSecret);
    });

    test('processes source map when available', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition
            .mockReturnValueOnce({ line: 1, column: 10 })
            .mockReturnValueOnce({ line: 1, column: 50 });

        // Mock fetch to return a simple successful response
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
        });

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockGetSourceMapUrl).toHaveBeenCalledWith(testUrl, content);
        expect(global.fetch).toHaveBeenCalledWith(expect.any(String));
    });

    test('falls back to bundled content when source map processing fails', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        
        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/app.js.map'));
        
        // Mock fetch to fail
        (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.content).toBe(JSON.stringify({
            api_key: mockApiKey,
            api_secret: mockApiSecret
        }));
        expect(result[0].sourceContent.contentFilename).toBe('app.js');
    });

    test('correctly identifies filename from URL', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const urlWithPath = 'https://example.com/path/to/bundle.min.js';

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, urlWithPath);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('bundle.min.js');
    });

    test('handles URL with no filename', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const urlWithoutFilename = 'https://example.com/';

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, urlWithoutFilename);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    test('processes source map with successful original position mapping', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockClear();
        mockFindSecretPosition
            .mockReturnValueOnce({ line: 5, column: 10 })
            .mockReturnValueOnce({ line: 8, column: 20 });

        // Mock successful source map processing
        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        mockConsumer.originalPositionFor
            .mockReturnValueOnce({ line: 15, column: 5, source: 'original.js' })
            .mockReturnValueOnce({ line: 18, column: 15, source: 'original.js' });

        const mockSourceContent = 'line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\nline14\nline15 api key here\nline16\nline17\nline18 secret here\nline19\nline20\nline21\nline22\nline23\nline24\nline25\nline26\nline27\nline28\nline29\nline30';
        mockConsumer.sourceContentFor.mockReturnValue(mockSourceContent);

        // Mock SourceMapConsumer constructor
        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
        });

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('original.js');
        expect(result[0].sourceContent.contentStartLineNum).toBe(5); // min(15,18) - 10
        expect(result[0].sourceContent.contentEndLineNum).toBe(28); // max(15,18) + 10
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([14, 17]); // line - 1
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });

    test('handles source map processing when findSecretPosition returns -1', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        
        // Reset and set up mock for this specific test
        mockFindSecretPosition.mockReset();
        mockFindSecretPosition
            .mockReturnValueOnce({ line: -1, column: -1 })
            .mockReturnValueOnce({ line: -1, column: -1 });

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

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js'); // Falls back to bundled content
        expect(mockFindSecretPosition).toHaveBeenCalledTimes(2);
        expect(mockConsumer.originalPositionFor).not.toHaveBeenCalled();
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });

    test('handles source map processing when originalPositionFor returns null source', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockClear();
        mockFindSecretPosition
            .mockReturnValueOnce({ line: 5, column: 10 })
            .mockReturnValueOnce({ line: 8, column: 20 });

        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        mockConsumer.originalPositionFor
            .mockReturnValueOnce({ line: 15, column: 5, source: null })
            .mockReturnValueOnce({ line: 18, column: 15, source: 'original.js' });

        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
        });

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js'); // Falls back to bundled content
        expect(mockConsumer.sourceContentFor).not.toHaveBeenCalled();
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });

    test('handles source map processing when sourceContentFor returns null', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockClear();
        mockFindSecretPosition
            .mockReturnValueOnce({ line: 5, column: 10 })
            .mockReturnValueOnce({ line: 8, column: 20 });

        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        mockConsumer.originalPositionFor
            .mockReturnValueOnce({ line: 15, column: 5, source: 'original.js' })
            .mockReturnValueOnce({ line: 18, column: 15, source: 'original.js' });

        mockConsumer.sourceContentFor.mockReturnValue(null);

        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":""}')
        });

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js'); // Falls back to bundled content
        expect(mockConsumer.sourceContentFor).toHaveBeenCalledWith('original.js');
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });

    test('handles source map processing when fetch response is not ok', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));

        global.fetch = jest.fn().mockResolvedValue({
            ok: false,
            status: 404
        });

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js'); // Falls back to bundled content
        expect(global.fetch).toHaveBeenCalledWith(sourceMapUrl);
    });

    test('handles source map processing when originalKeyPos.source has no filename', async () => {
        const content = `const key="${mockApiKey}";const secret="${mockApiSecret}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockClear();
        mockFindSecretPosition
            .mockReturnValueOnce({ line: 5, column: 10 })
            .mockReturnValueOnce({ line: 8, column: 20 });

        // Mock successful source map processing but with empty source path
        const mockConsumer = {
            originalPositionFor: jest.fn(),
            sourceContentFor: jest.fn(),
            destroy: jest.fn()
        };

        mockConsumer.originalPositionFor
            .mockReturnValueOnce({ line: 15, column: 5, source: '/' }) // Source path that results in empty pop()
            .mockReturnValueOnce({ line: 18, column: 15, source: '/' });

        const mockSourceContent = 'line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\nline14\nline15 api key here\nline16\nline17\nline18 secret here\nline19\nline20\nline21\nline22\nline23\nline24\nline25\nline26\nline27\nline28\nline29\nline30';
        mockConsumer.sourceContentFor.mockReturnValue(mockSourceContent);

        // Mock SourceMapConsumer constructor
        const SourceMapConsumerSpy = jest.spyOn(require('../../../../external/source-map'), 'SourceMapConsumer');
        SourceMapConsumerSpy.mockResolvedValue(mockConsumer);

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('{"version":3,"sources":["/"],"mappings":""}')
        });

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        const result = await detectGeminiKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe(''); // Empty filename when source path has no filename
        expect(result[0].sourceContent.contentStartLineNum).toBe(5); // min(15,18) - 10
        expect(result[0].sourceContent.contentEndLineNum).toBe(28); // max(15,18) + 10
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([14, 17]); // line - 1
        expect(mockConsumer.destroy).toHaveBeenCalled();

        SourceMapConsumerSpy.mockRestore();
    });
});