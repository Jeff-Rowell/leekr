import { detectGroqKeys } from './groq';
import { validateGroqCredentials } from '../../../utils/validators/groq/groq';
import { getExistingFindings, findSecretPosition } from '../../../utils/helpers/common';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

jest.mock('../../../utils/validators/groq/groq');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/accuracy/entropy');
jest.mock('../../../utils/accuracy/programmingPatterns');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');

const mockValidateGroqCredentials = validateGroqCredentials as jest.MockedFunction<typeof validateGroqCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;
const mockIsProgrammingPattern = isProgrammingPattern as jest.MockedFunction<typeof isProgrammingPattern>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

describe('detectGroqKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 0 });
        mockCalculateShannonEntropy.mockReturnValue(5);
        mockIsProgrammingPattern.mockReturnValue(false);
        mockComputeFingerprint.mockResolvedValue('test-fingerprint');
        mockValidateGroqCredentials.mockResolvedValue({ valid: true, error: null });
        
        // Reset source map related mocks
        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(null);
        
        // Reset global mocks
        global.fetch = jest.fn();
        global.chrome = {
            runtime: {
                getURL: jest.fn((path: string) => `chrome-extension://extension-id/${path}`)
            }
        } as any;
    });

    it('should return empty array when no matches found', async () => {
        const content = 'This is some content without any Groq keys';
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should detect valid Groq API key', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toEqual(expect.objectContaining({
            secretType: 'Groq',
            fingerprint: 'test-fingerprint',
            secretValue: {
                match: {
                    apiKey: apiKey
                }
            },
            filePath: 'test.js',
            url: url,
            type: 'Groq API Key',
            validity: 'valid'
        }));
    });

    it('should skip keys with incorrect length', async () => {
        const shortKey = 'gsk_shortkey';
        const content = `const groqKey = "${shortKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should skip keys with low entropy', async () => {
        mockCalculateShannonEntropy.mockReturnValue(2);
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
        expect(mockCalculateShannonEntropy).toHaveBeenCalledWith(apiKey);
    });

    it('should skip programming patterns', async () => {
        mockIsProgrammingPattern.mockReturnValue(true);
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
        expect(mockIsProgrammingPattern).toHaveBeenCalledWith(apiKey);
    });

    it('should skip already found keys with match structure', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const existingFinding = {
            secretType: 'Groq',
            secretValue: {
                match1: { match: { apiKey: apiKey } }
            }
        };
        mockGetExistingFindings.mockResolvedValue([existingFinding] as any);

        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should skip already found keys with direct apiKey structure', async () => {
        const apiKey = 'gsk_' + 'b'.repeat(52);
        const existingFinding = {
            secretType: 'Groq',
            secretValue: {
                match1: { apiKey: apiKey }
            }
        };
        mockGetExistingFindings.mockResolvedValue([existingFinding] as any);

        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should skip invalid keys', async () => {
        mockValidateGroqCredentials.mockResolvedValue({ valid: false, error: null });
        const apiKey = 'gsk_' + 'c'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith(apiKey);
    });

    it('should handle multiple keys in content', async () => {
        const apiKey1 = 'gsk_' + 'a'.repeat(52);
        const apiKey2 = 'gsk_' + 'b'.repeat(52);
        const content = `const key1 = "${apiKey1}"; const key2 = "${apiKey2}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toHaveLength(2);
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey1);
        expect((result[1].secretValue as any).match.apiKey).toBe(apiKey2);
    });

    it('should handle empty match groups', async () => {
        const content = 'gsk_';
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should handle regex matches with empty capture groups', async () => {
        // Mock a regex match where match[1] is undefined/empty
        const originalMatchAll = String.prototype.matchAll;
        String.prototype.matchAll = jest.fn().mockReturnValue([
            Object.assign(['gsk_test', undefined], { index: 0, input: 'test', groups: undefined })
        ]);

        const content = 'some content';
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
        
        // Restore original method
        String.prototype.matchAll = originalMatchAll;
    });

    it('should handle keys with incorrect length after trimming', async () => {
        // Test with a key that's 55 characters (should be 56)
        const shortKey = 'gsk_' + 'a'.repeat(51); // 55 total chars
        const content = `const groqKey = "${shortKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should handle regex matches with empty trimmed keys', async () => {
        // Create a scenario where match[1] exists but when trimmed becomes empty or wrong length
        // Mock the regex to return a match with whitespace that trims to wrong length
        const originalPattern = require('../../../config/patterns').patterns['Groq API Key'].pattern;
        const mockPatterns = require('../../../config/patterns').patterns;
        mockPatterns['Groq API Key'].pattern = {
            source: originalPattern.source,
            flags: originalPattern.flags,
            // Override matchAll to return a custom match
        };
        
        // Mock String.matchAll to return matches with empty or invalid trimmed content
        const originalMatchAll = String.prototype.matchAll;
        String.prototype.matchAll = jest.fn().mockReturnValue([
            Object.assign(['gsk_' + 'a'.repeat(52), '   '], { index: 0, input: 'test', groups: undefined })
        ]);

        const content = 'some content';
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toEqual([]);
        
        // Restore original method
        String.prototype.matchAll = originalMatchAll;
    });

    it('should handle source map processing when source map is available', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';
        const mockSourceMapUrl = new URL('https://example.com/test.js.map');

        // Mock getSourceMapUrl to return a source map URL
        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(mockSourceMapUrl);
        
        // Mock findSecretPosition
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

        const result = await detectGroqKeys(content, url);

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
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';
        const mockSourceMapUrl = new URL('https://example.com/test.js.map');

        // Mock getSourceMapUrl to return a source map URL
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

        const result = await detectGroqKeys(content, url);

        expect(result).toHaveLength(1);
        // Should use default source content when originalPosition.source is null
        expect(result[0].sourceContent).toMatchObject({
            content: apiKey,
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle source map processing when sourceContentFor returns null', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';
        const mockSourceMapUrl = new URL('https://example.com/test.js.map');

        // Mock getSourceMapUrl to return a source map URL
        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(mockSourceMapUrl);

        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["App.tsx"]}'),
        });

        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn(() => ({
                    source: 'App.tsx',
                    line: 100,
                    column: 15
                })),
                sourceContentFor: jest.fn().mockReturnValue(null), // No source content available
            });
        });

        const sourceMapModule = require('../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectGroqKeys(content, url);

        expect(result).toHaveLength(1);
        // Should use default source content when sourceContentFor returns null
        expect(result[0].sourceContent).toMatchObject({
            content: apiKey,
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle source map processing with fetch error', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';
        const mockSourceMapUrl = new URL('https://example.com/test.js.map');

        // Mock getSourceMapUrl to return a source map URL
        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(mockSourceMapUrl);

        // Mock fetch to reject (network error)
        (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

        const result = await detectGroqKeys(content, url);

        expect(result).toHaveLength(1);
        // Should fall back to default source content when fetch fails
        expect(result[0].sourceContent).toMatchObject({
            content: apiKey,
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle whitespace in matched keys', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "  ${apiKey}  ";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey);
    });

    it('should handle URL ending with slash (empty filename)', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/folder/'; // URL ending with slash

        const result = await detectGroqKeys(content, url);

        expect(result).toHaveLength(1);
        // Should use empty string when url.split('/').pop() returns undefined
        expect(result[0].sourceContent.contentFilename).toBe('');
        expect(result[0].filePath).toBe('');
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey);
    });

    it('should handle findings with different secret types', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const existingFinding = {
            secretType: 'OpenAI',
            secretValue: {
                match1: { apiKey: apiKey }
            }
        };
        mockGetExistingFindings.mockResolvedValue([existingFinding] as any);

        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey);
    });

    it('should set correct source content properties', async () => {
        const apiKey = 'gsk_' + 'a'.repeat(52);
        const content = `const groqKey = "${apiKey}";`;
        const url = 'https://example.com/folder/test.js';

        const result = await detectGroqKeys(content, url);

        expect(result[0].sourceContent).toEqual({
            content: apiKey,
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });
});