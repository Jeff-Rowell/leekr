import { detectMailgunKeys } from './mailgun';
import { validateMailgunCredentials } from '../../../utils/validators/mailgun/mailgun';
import { getExistingFindings, findSecretPosition } from '../../../utils/helpers/common';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

jest.mock('../../../utils/validators/mailgun/mailgun');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/accuracy/entropy');
jest.mock('../../../utils/accuracy/programmingPatterns');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');

const mockValidateMailgunCredentials = validateMailgunCredentials as jest.MockedFunction<typeof validateMailgunCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;
const mockIsProgrammingPattern = isProgrammingPattern as jest.MockedFunction<typeof isProgrammingPattern>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

describe('detectMailgunKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 0 });
        mockCalculateShannonEntropy.mockReturnValue(5);
        mockIsProgrammingPattern.mockReturnValue(false);
        mockComputeFingerprint.mockResolvedValue('test-fingerprint');
        mockValidateMailgunCredentials.mockResolvedValue({ valid: true, error: '' });
        
        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(null);
        
        global.fetch = jest.fn();
        global.chrome = {
            runtime: {
                getURL: jest.fn((path: string) => `chrome-extension://extension-id/${path}`)
            }
        } as any;
    });

    it('should return empty array when no matches found', async () => {
        const content = 'This is some content without any Mailgun keys';
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should detect valid 72-character Mailgun API key', async () => {
        const apiKey = 'a'.repeat(72);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toEqual(expect.objectContaining({
            secretType: 'Mailgun',
            fingerprint: 'test-fingerprint',
            secretValue: {
                match: {
                    apiKey: apiKey
                }
            },
            filePath: 'test.js',
            url: url,
            type: 'Mailgun API Key',
            validity: 'valid'
        }));
    });

    it('should detect valid key-prefixed Mailgun API key', async () => {
        const apiKey = 'key-' + 'a'.repeat(32);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toEqual(expect.objectContaining({
            secretType: 'Mailgun',
            fingerprint: 'test-fingerprint',
            secretValue: {
                match: {
                    apiKey: apiKey
                }
            },
            filePath: 'test.js',
            url: url,
            type: 'Mailgun API Key',
            validity: 'valid'
        }));
    });

    it('should detect valid hex-format Mailgun API key', async () => {
        const apiKey = 'a'.repeat(32) + '-' + 'b'.repeat(8) + '-' + 'c'.repeat(8);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toEqual(expect.objectContaining({
            secretType: 'Mailgun',
            fingerprint: 'test-fingerprint',
            secretValue: {
                match: {
                    apiKey: apiKey
                }
            },
            filePath: 'test.js',
            url: url,
            type: 'Mailgun API Key',
            validity: 'valid'
        }));
    });

    it('should skip keys with low entropy', async () => {
        mockCalculateShannonEntropy.mockReturnValue(2);
        const apiKey = 'a'.repeat(72);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
        expect(mockCalculateShannonEntropy).toHaveBeenCalledWith(apiKey);
    });

    it('should skip programming patterns', async () => {
        mockIsProgrammingPattern.mockReturnValue(true);
        const apiKey = 'key-' + 'a'.repeat(32);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
        expect(mockIsProgrammingPattern).toHaveBeenCalledWith(apiKey);
    });

    it('should skip already found keys with match structure', async () => {
        const apiKey = 'key-' + 'a'.repeat(32);
        const existingFinding = {
            secretType: 'Mailgun',
            secretValue: {
                match1: { match: { apiKey: apiKey } }
            }
        };
        mockGetExistingFindings.mockResolvedValue([existingFinding] as any);

        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should skip already found keys with direct apiKey structure', async () => {
        const apiKey = 'key-' + 'b'.repeat(32);
        const existingFinding = {
            secretType: 'Mailgun',
            secretValue: {
                match1: { apiKey: apiKey }
            }
        };
        mockGetExistingFindings.mockResolvedValue([existingFinding] as any);

        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should skip invalid keys', async () => {
        mockValidateMailgunCredentials.mockResolvedValue({ valid: false, error: '' });
        const apiKey = 'key-' + 'c'.repeat(32);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith(apiKey);
    });

    it('should handle multiple keys in content', async () => {
        const apiKey1 = 'key-' + 'a'.repeat(32);
        const apiKey2 = 'b'.repeat(72);
        const content = `const key1 = "${apiKey1}"; const key2 = "${apiKey2}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(2);
        // Note: Original Token pattern is processed first, so 72-char string appears first
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey2);
        expect((result[1].secretValue as any).match.apiKey).toBe(apiKey1);
    });

    it('should handle empty match groups', async () => {
        const content = 'key-';
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should handle regex matches with empty capture groups', async () => {
        const originalMatchAll = String.prototype.matchAll;
        String.prototype.matchAll = jest.fn().mockReturnValue([
            Object.assign(['key-test', undefined], { index: 0, input: 'test', groups: undefined })
        ]);

        const content = 'some content';
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
        
        String.prototype.matchAll = originalMatchAll;
    });

    it('should handle regex matches with whitespace-only capture groups', async () => {
        const originalMatchAll = String.prototype.matchAll;
        String.prototype.matchAll = jest.fn().mockReturnValue([
            Object.assign(['key-   ', '   '], { index: 0, input: 'test', groups: undefined })
        ]);

        const content = 'some content';
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toEqual([]);
        
        String.prototype.matchAll = originalMatchAll;
    });

    it('should handle source map processing when source map is available', async () => {
        const apiKey = 'key-' + 'a'.repeat(32);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';
        const mockSourceMapUrl = new URL('https://example.com/test.js.map');

        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(mockSourceMapUrl);
        
        mockFindSecretPosition.mockReturnValue({ line: 25, column: 10 });

        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["App.tsx"],"sourcesContent":["console.log(\\"hello\\");"]}'),
        });

        const sourceContent = 'console.log("hello");';
        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn(() => ({
                    source: 'App.tsx',
                    line: 100,
                    column: 15
                })),
                sourceContentFor: jest.fn().mockReturnValue(sourceContent),
            });
        });

        const sourceMapModule = require('../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: sourceContent,
            contentFilename: 'App.tsx',
            exactMatchNumbers: [100],
            contentStartLineNum: 95,
            contentEndLineNum: 105,
        });
        expect(sourceMapModule.SourceMapConsumer.initialize).toHaveBeenCalledWith({
            'lib/mappings.wasm': 'chrome-extension://extension-id/libs/mappings.wasm'
        });
    });

    it('should handle source map processing when originalPosition source is null', async () => {
        const apiKey = 'a'.repeat(72);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';
        const mockSourceMapUrl = new URL('https://example.com/test.js.map');

        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(mockSourceMapUrl);

        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["App.tsx"]}'),
        });

        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn(() => ({
                    source: null,
                    line: null,
                    column: null
                })),
                sourceContentFor: jest.fn(),
            });
        });

        const sourceMapModule = require('../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: apiKey,
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle source map processing with fetch error', async () => {
        const apiKey = 'key-' + 'a'.repeat(32);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';
        const mockSourceMapUrl = new URL('https://example.com/test.js.map');

        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(mockSourceMapUrl);

        (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: apiKey,
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle whitespace in matched keys', async () => {
        const apiKey = 'key-' + 'a'.repeat(32);
        const content = `const mailgunKey = "  ${apiKey}  ";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey);
    });

    it('should handle URL ending with slash (empty filename)', async () => {
        const apiKey = 'a'.repeat(72);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/folder/';

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('');
        expect(result[0].filePath).toBe('');
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey);
    });

    it('should handle findings with different secret types', async () => {
        const apiKey = 'key-' + 'a'.repeat(32);
        const existingFinding = {
            secretType: 'OpenAI',
            secretValue: {
                match1: { apiKey: apiKey }
            }
        };
        mockGetExistingFindings.mockResolvedValue([existingFinding] as any);

        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey);
    });

    it('should set correct source content properties', async () => {
        const apiKey = 'key-' + 'a'.repeat(32);
        const content = `const mailgunKey = "${apiKey}";`;
        const url = 'https://example.com/folder/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result[0].sourceContent).toEqual({
            content: apiKey,
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle multiple pattern types in one content', async () => {
        const apiKey1 = 'a'.repeat(72);  // Original pattern
        const apiKey2 = 'key-' + 'b'.repeat(32);  // Key pattern
        const apiKey3 = 'c'.repeat(32) + '-' + 'd'.repeat(8) + '-' + 'e'.repeat(8);  // Hex pattern
        const content = `
            const original = "${apiKey1}";
            const keyFormat = "${apiKey2}";
            const hexFormat = "${apiKey3}";
        `;
        const url = 'https://example.com/test.js';

        const result = await detectMailgunKeys(content, url);

        expect(result).toHaveLength(3);
        const apiKeys = result.map(r => (r.secretValue as any).match.apiKey);
        expect(apiKeys).toContain(apiKey1);
        expect(apiKeys).toContain(apiKey2);
        expect(apiKeys).toContain(apiKey3);
    });
});