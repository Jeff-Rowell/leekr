import { detectMailchimpKeys } from './mailchimp';
import { validateMailchimpCredentials } from '../../../utils/validators/mailchimp/mailchimp';
import { getExistingFindings, findSecretPosition } from '../../../utils/helpers/common';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { Finding } from '../../../types/findings.types';
import * as sourceMap from '../../../../external/source-map';

// Mock dependencies
jest.mock('../../../utils/validators/mailchimp/mailchimp');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/accuracy/entropy');
jest.mock('../../../utils/accuracy/programmingPatterns');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');

const mockValidateMailchimpCredentials = validateMailchimpCredentials as jest.MockedFunction<typeof validateMailchimpCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;
const mockIsProgrammingPattern = isProgrammingPattern as jest.MockedFunction<typeof isProgrammingPattern>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

// Mock chrome runtime
global.chrome = {
    ...global.chrome,
    runtime: {
        ...global.chrome?.runtime,
        getURL: jest.fn(() => 'chrome-extension://test-id/')
    }
} as any;

// Mock global fetch
global.fetch = jest.fn() as jest.MockedFunction<typeof fetch>;

describe('detectMailchimpKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockCalculateShannonEntropy.mockReturnValue(4.5);
        mockIsProgrammingPattern.mockReturnValue(false);
        mockGetExistingFindings.mockResolvedValue([]);
        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });
        mockComputeFingerprint.mockResolvedValue('test-fingerprint-123');
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 0 });
        
        // Reset source map related mocks
        const mockGetSourceMapUrl = require('../../../utils/helpers/common').getSourceMapUrl as jest.MockedFunction<any>;
        mockGetSourceMapUrl.mockReturnValue(null);
    });

    it('should return empty array for content with no matches', async () => {
        const content = 'This is some content without any API keys';
        const url = 'https://example.com/test.js';

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should detect valid Mailchimp API key', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailchimpKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            secretType: 'Mailchimp',
            fingerprint: 'test-fingerprint-123',
            secretValue: {
                match: {
                    apiKey: apiKey
                }
            },
            filePath: 'test.js',
            url: url,
            type: 'Mailchimp API Key',
            validity: 'valid'
        });
    });

    it('should skip API keys with low entropy', async () => {
        const apiKey = 'aaaa1111bbbb2222cccc3333dddd4444-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        mockCalculateShannonEntropy.mockReturnValue(3.0); // Below threshold

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);
        expect(mockCalculateShannonEntropy).toHaveBeenCalledWith(apiKey);
    });

    it('should skip programming patterns', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        mockIsProgrammingPattern.mockReturnValue(true);

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);
        expect(mockIsProgrammingPattern).toHaveBeenCalledWith(apiKey);
    });

    it('should skip already found API keys', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const existingFinding: Finding = {
            fingerprint: 'existing-fingerprint',
            secretType: 'Mailchimp',
            secretValue: {
                match: { apiKey: apiKey }
            } as any,
            numOccurrences: 1,
            occurrences: new Set(),
            validity: 'valid',
            validatedAt: undefined
        };

        mockGetExistingFindings.mockResolvedValue([existingFinding]);

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should skip already found API keys with different structure', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const existingFinding: Finding = {
            fingerprint: 'existing-fingerprint',
            secretType: 'Mailchimp',
            secretValue: {
                occurrence1: { apiKey: apiKey }
            } as any,
            numOccurrences: 1,
            occurrences: new Set(),
            validity: 'valid',
            validatedAt: undefined
        };

        mockGetExistingFindings.mockResolvedValue([existingFinding]);

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should skip invalid API keys', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: false, error: 'Invalid API key' });

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);
        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith(apiKey);
    });

    it('should skip empty or null matches', async () => {
        const content = 'some content with partial match -us12 but no full key';
        const url = 'https://example.com/test.js';

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);
    });

    it('should skip whitespace-only matches', async () => {
        // This test ensures that trimmed empty strings are handled
        const apiKey = '   '; // This won't actually match the pattern, but testing the trim logic
        const content = 'const mailchimpKey = "abcd1234567890abcd1234567890abcd-us12";';
        const url = 'https://example.com/test.js';

        // Mock the trim to return empty string (simulating edge case)
        const originalTrim = String.prototype.trim;
        String.prototype.trim = jest.fn().mockReturnValue('');

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);

        // Restore original trim
        String.prototype.trim = originalTrim;
    });

    it('should handle multiple API keys in content', async () => {
        const apiKey1 = 'abcd1234567890abcd1234567890abcd-us12';
        const apiKey2 = 'efgh5678901234efgh5678901234efgh-us15';
        const content = `
            const key1 = "${apiKey1}";
            const key2 = "${apiKey2}";
        `;
        const url = 'https://example.com/test.js';

        // Mock that the second key is already found to test the deduplication logic
        const existingFinding: Finding = {
            fingerprint: 'existing-fingerprint',
            secretType: 'Mailchimp',
            secretValue: {
                match: { apiKey: apiKey2 }
            } as any,
            numOccurrences: 1,
            occurrences: new Set(),
            validity: 'valid',
            validatedAt: undefined
        };
        mockGetExistingFindings.mockResolvedValue([existingFinding]);
        
        mockComputeFingerprint.mockResolvedValue('fingerprint-1');

        const result = await detectMailchimpKeys(content, url);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.apiKey).toBe(apiKey1);
    });

    it('should handle source map processing', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        // Mock source map response
        const mockSourceMapResponse = {
            text: jest.fn().mockResolvedValue('{"version":3,"sources":["original.ts"]}')
        };
        (global.fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue(mockSourceMapResponse as any);

        // Add source map comment to content
        const contentWithSourceMap = content + '\n//# sourceMappingURL=test.js.map';

        const result = await detectMailchimpKeys(contentWithSourceMap, url);

        // Should still return results even if source map processing has issues
        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('test.js');
    });

    it('should handle source map processing errors gracefully', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        // Mock source map response that fails
        (global.fetch as jest.MockedFunction<typeof fetch>).mockRejectedValue(new Error('Source map fetch failed'));

        // Add source map comment to content
        const contentWithSourceMap = content + '\n//# sourceMappingURL=test.js.map';

        const result = await detectMailchimpKeys(contentWithSourceMap, url);

        // Should still return results even if source map processing fails
        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('test.js');
    });

    it('should handle different datacenter formats', async () => {
        const testCases = [
            'abcd1234567890abcd1234567890abcd-us1',
            'abcd1234567890abcd1234567890abcd-us10',
            'abcd1234567890abcd1234567890abcd-us20'
        ];

        for (const apiKey of testCases) {
            const content = `const key = "${apiKey}";`;
            const url = 'https://example.com/test.js';

            mockComputeFingerprint.mockResolvedValue(`fingerprint-${apiKey}`);

            const result = await detectMailchimpKeys(content, url);

            expect(result).toHaveLength(1);
            expect((result[0].secretValue as any).match.apiKey).toBe(apiKey);
        }
    });

    it('should set correct source content properties', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const result = await detectMailchimpKeys(content, url);

        expect(result[0].sourceContent).toMatchObject({
            content: apiKey,
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle findings with non-Mailchimp secret types', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const existingFinding: Finding = {
            fingerprint: 'existing-fingerprint',
            secretType: 'OpenAI', // Different secret type
            secretValue: {
                match: { apiKey: apiKey }
            } as any,
            numOccurrences: 1,
            occurrences: new Set(),
            validity: 'valid',
            validatedAt: undefined
        };

        mockGetExistingFindings.mockResolvedValue([existingFinding]);

        const result = await detectMailchimpKeys(content, url);

        // Should still detect since it's a different secret type
        expect(result).toHaveLength(1);
    });

    it('should handle regex matches with empty capture groups', async () => {
        // Mock a regex match where match[1] is undefined/empty
        const originalMatchAll = String.prototype.matchAll;
        String.prototype.matchAll = jest.fn().mockReturnValue([
            Object.assign(['abcd1234567890abcd1234567890abcd-us12', undefined], { index: 0, input: 'test', groups: undefined })
        ]);

        const content = 'some content';
        const url = 'https://example.com/test.js';

        const result = await detectMailchimpKeys(content, url);

        expect(result).toEqual([]);
        
        // Restore original method
        String.prototype.matchAll = originalMatchAll;
    });

    it('should handle source map processing when source map is available', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
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

        const result = await detectMailchimpKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: sourceContent,
            contentFilename: 'App.tsx',
            exactMatchNumbers: [100],
            contentStartLineNum: 95,
            contentEndLineNum: 105,
        });
        expect(sourceMapModule.SourceMapConsumer.initialize).toHaveBeenCalledWith({
            'lib/mappings.wasm': 'chrome-extension://test-id/'
        });
    });

    it('should handle source map processing when originalPosition source is null', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
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

        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn(() => ({
                    source: null, // No source
                    line: 100,
                    column: 15
                })),
                sourceContentFor: jest.fn().mockReturnValue(null),
            });
        });

        const sourceMapModule = require('../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectMailchimpKeys(content, url);

        expect(result).toHaveLength(1);
        // Should use default source content when original position source is null
        expect(result[0].sourceContent).toMatchObject({
            content: apiKey,
            contentFilename: 'test.js',
            exactMatchNumbers: [-1],
            contentStartLineNum: -1,
            contentEndLineNum: -1,
        });
    });

    it('should handle source map processing when originalSource is null', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
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

        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn(() => ({
                    source: 'App.tsx',
                    line: 100,
                    column: 15
                })),
                sourceContentFor: jest.fn().mockReturnValue(null), // No source content
            });
        });

        const sourceMapModule = require('../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectMailchimpKeys(content, url);

        expect(result).toHaveLength(1);
        // Should use default source content when original source content is null
        expect(result[0].sourceContent).toMatchObject({
            content: apiKey,
            contentFilename: 'test.js',
            exactMatchNumbers: [-1],
            contentStartLineNum: -1,
            contentEndLineNum: -1,
        });
    });

    it('should handle URL with no filename', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/'; // URL ending with slash

        const result = await detectMailchimpKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].filePath).toBe('');
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    it('should handle empty URL', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = ''; // Empty URL

        const result = await detectMailchimpKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].filePath).toBe('');
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    it('should detect duplicate finding with direct apiKey property in secretValue', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const existingFinding: Finding = {
            fingerprint: 'existing-fingerprint',
            secretType: 'Mailchimp',
            secretValue: {
                firstOccurrence: {
                    apiKey: apiKey // This should match the first condition (mailchimpMatch.apiKey === apiKey)
                }
            } as any,
            numOccurrences: 1,
            occurrences: new Set(),
            validity: 'valid',
            validatedAt: undefined
        };

        mockGetExistingFindings.mockResolvedValue([existingFinding]);

        const result = await detectMailchimpKeys(content, url);

        // Should be filtered out as duplicate
        expect(result).toEqual([]);
    });

    it('should detect duplicate finding with nested match structure in secretValue', async () => {
        const apiKey = 'abcd1234567890abcd1234567890abcd-us12';
        const content = `const mailchimpKey = "${apiKey}";`;
        const url = 'https://example.com/test.js';

        const existingFinding: Finding = {
            fingerprint: 'existing-fingerprint',
            secretType: 'Mailchimp',
            secretValue: {
                firstOccurrence: {
                    match: {
                        apiKey: apiKey // This should match the second condition (mailchimpMatch.match.apiKey === apiKey)
                    }
                }
            } as any,
            numOccurrences: 1,
            occurrences: new Set(),
            validity: 'valid',
            validatedAt: undefined
        };

        mockGetExistingFindings.mockResolvedValue([existingFinding]);

        const result = await detectMailchimpKeys(content, url);

        // Should be filtered out as duplicate
        expect(result).toEqual([]);
    });
});