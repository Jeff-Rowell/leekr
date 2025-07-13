import { detectDeepSeekKeys } from './deepseek';
import { validateDeepSeekApiKey } from '../../../utils/validators/deepseek/deepseek';
import { patterns } from '../../../config/patterns';
import * as common from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { DeepSeekOccurrence, DeepSeekSecretValue } from '../../../types/deepseek';

jest.mock('../../../utils/validators/deepseek/deepseek');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');

global.fetch = jest.fn();
global.chrome = {
    runtime: {
        getURL: jest.fn((path: string) => `chrome-extension://extension-id/${path}`)
    }
} as any;

const mockValidateDeepSeekApiKey = validateDeepSeekApiKey as jest.MockedFunction<typeof validateDeepSeekApiKey>;
const mockGetExistingFindings = common.getExistingFindings as jest.MockedFunction<typeof common.getExistingFindings>;
const mockGetSourceMapUrl = common.getSourceMapUrl as jest.MockedFunction<typeof common.getSourceMapUrl>;
const mockFindSecretPosition = common.findSecretPosition as jest.MockedFunction<typeof common.findSecretPosition>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

describe('detectDeepSeekKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        
        // Default mock implementations
        mockValidateDeepSeekApiKey.mockResolvedValue({ valid: true });
        mockGetExistingFindings.mockResolvedValue([]);
        mockGetSourceMapUrl.mockReturnValue(null);
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 20 });
        mockComputeFingerprint.mockResolvedValue('test-fingerprint-123');
    });

    test('should detect valid DeepSeek API key', async () => {
        const content = 'const apiKey = "sk-test1234567890abcd1234567890abcd";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledWith('sk-test1234567890abcd1234567890abcd');
        
        const occurrence = occurrences[0] as DeepSeekOccurrence;
        expect(occurrence).toEqual({
            filePath: url,
            fingerprint: 'test-fingerprint-123',
            type: 'API Key',
            secretType: 'DeepSeek',
            secretValue: {
                match: {
                    apiKey: 'sk-test1234567890abcd1234567890abcd'
                }
            },
            sourceContent: {
                content: JSON.stringify({
                    apiKey: 'sk-test1234567890abcd1234567890abcd'
                }),
                contentFilename: 'file.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            },
            url: url
        });
    });

    test('should return empty array when no matches found', async () => {
        const content = 'const apiKey = "invalid-key";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences).toHaveLength(0);
        expect(mockValidateDeepSeekApiKey).not.toHaveBeenCalled();
    });

    test('should filter out invalid API keys', async () => {
        mockValidateDeepSeekApiKey.mockResolvedValue({ valid: false, error: 'Invalid API key' });
        
        const content = 'const apiKey = "sk-test1234567890abcd1234567890abcd";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences).toHaveLength(0);
        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledWith('sk-test1234567890abcd1234567890abcd');
    });

    test('should deduplicate API keys', async () => {
        const content = `
            const key1 = "sk-test1234567890abcd1234567890abcd";
            const key2 = "sk-test1234567890abcd1234567890abcd";
        `;
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledTimes(1);
    });

    test('should skip keys that already exist in findings', async () => {
        const existingFindings = [
            {
                secretValue: {
                    someKey: {
                        match: {
                            apiKey: 'sk-test1234567890abcd1234567890abcd'
                        }
                    }
                }
            }
        ];
        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const content = 'const apiKey = "sk-test1234567890abcd1234567890abcd";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences).toHaveLength(0);
        expect(mockValidateDeepSeekApiKey).not.toHaveBeenCalled();
    });

    test('should handle multiple different API keys', async () => {
        const content = `
            const key1 = "sk-test1234567890abcd1234567890abcd";
            const key2 = "sk-abcd1234567890efgh1234567890ijkl";
        `;
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences).toHaveLength(2);
        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledTimes(2);
        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledWith('sk-test1234567890abcd1234567890abcd');
        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledWith('sk-abcd1234567890efgh1234567890ijkl');
    });

    test('should extract filename correctly', async () => {
        const content = 'const apiKey = "sk-test1234567890abcd1234567890abcd";';
        const url = 'http://example.com/path/to/deep/file.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences[0].sourceContent.contentFilename).toBe('file.js');
    });

    test('should handle URL without filename', async () => {
        const content = 'const apiKey = "sk-test1234567890abcd1234567890abcd";';
        const url = 'http://example.com/';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences[0].sourceContent.contentFilename).toBe('');
    });

    test('should use computeFingerprint for fingerprint generation', async () => {
        const content = 'const apiKey = "sk-test1234567890abcd1234567890abcd";';
        const url = 'http://example.com/file.js';

        await detectDeepSeekKeys(content, url);

        expect(mockComputeFingerprint).toHaveBeenCalledWith({
            apiKey: 'sk-test1234567890abcd1234567890abcd'
        });
    });

    test('should handle source map processing', async () => {
        const mockSourceMapUrl = new URL('http://example.com/app.js.map');
        const mockSourceMapContent = '{"version":3,"sources":["src/app.js"],"mappings":"AAAA"}';
        const mockOriginalSource = 'const deepSeekKey = "sk-test1234567890abcd1234567890abcd";';
        
        mockGetSourceMapUrl.mockReturnValue(mockSourceMapUrl);
        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve(mockSourceMapContent)
        });

        const sourceMapModule = require('../../../../external/source-map');
        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: 'src/app.js',
                line: 1,
                column: 20
            }),
            sourceContentFor: jest.fn().mockReturnValue(mockOriginalSource)
        };
        sourceMapModule.SourceMapConsumer = {
            initialize: jest.fn(),
            with: jest.fn((content, options, callback) => callback(mockConsumer))
        };

        const content = 'var t="sk-test1234567890abcd1234567890abcd";';
        const url = 'http://example.com/bundle.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentFilename).toBe('src/app.js');
        expect(occurrences[0].sourceContent.content).toBe(mockOriginalSource);
        expect(occurrences[0].sourceContent.exactMatchNumbers).toEqual([1]);
        expect(occurrences[0].sourceContent.contentStartLineNum).toBe(-4);
        expect(occurrences[0].sourceContent.contentEndLineNum).toBe(6);
    });

    test('should fallback gracefully when source map processing fails', async () => {
        const mockSourceMapUrl = new URL('http://example.com/app.js.map');
        const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
        
        mockGetSourceMapUrl.mockReturnValue(mockSourceMapUrl);
        (global.fetch as jest.Mock).mockRejectedValue(new Error('Failed to fetch source map'));

        const content = 'var t="sk-test1234567890abcd1234567890abcd";';
        const url = 'http://example.com/bundle.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentFilename).toBe('bundle.js');
        expect(consoleWarnSpy).toHaveBeenCalledWith('Failed to process source map for DeepSeek detection:', expect.any(Error));
        
        consoleWarnSpy.mockRestore();
    });

    test('should match the correct DeepSeek API key pattern', () => {
        // Test that our pattern matches valid DeepSeek keys
        const pattern = patterns['DeepSeek API Key'].pattern;
        
        // Valid keys (35 characters total: sk- + 32 characters)
        expect('sk-test1234567890abcd1234567890abcd'.match(pattern)).toBeTruthy();
        expect('sk-ABCD1234567890abcd1234567890ABCD'.match(pattern)).toBeTruthy();
        expect('sk-aBcD1234567890eFgH1234567890ijKl'.match(pattern)).toBeTruthy();
        
        // Invalid keys
        expect('ak-test1234567890abcd1234567890abcd'.match(pattern)).toBeFalsy(); // wrong prefix
        expect('sk-test123456789012345'.match(pattern)).toBeFalsy(); // too short
        expect('sk-test1234567890abcd1234567890abcd123'.match(pattern)).toBeFalsy(); // too long
        expect('sk-test!@#$567890abcd1234567890abcd'.match(pattern)).toBeFalsy(); // invalid chars
    });

    test('should not process keys that do not match the exact expected structure', async () => {
        // Test with keys that might partially match but should be filtered out
        const content = `
            const shortKey = "sk-tooshort";
            const longKey = "sk-test1234567890abcd1234567890abcdextra";
            const wrongPrefix = "ak-test1234567890abcd1234567890abcd";
            const validKey = "sk-test1234567890abcd1234567890abcd";
        `;
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepSeekKeys(content, url);

        // Only the valid key should be processed
        expect(occurrences).toHaveLength(1);
        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledTimes(1);
        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledWith('sk-test1234567890abcd1234567890abcd');
    });
});