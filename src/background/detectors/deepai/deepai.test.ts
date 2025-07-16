import { detectDeepAIKeys } from './deepai';
import * as common from '../../../utils/helpers/common';
import * as validators from '../../../utils/validators/deepai/deepai';
import * as computeFingerprint from '../../../utils/helpers/computeFingerprint';

jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/validators/deepai/deepai');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');

global.fetch = jest.fn();
global.chrome = {
    runtime: {
        getURL: jest.fn((path: string) => `chrome-extension://extension-id/${path}`)
    }
} as any;

describe('detectDeepAIKeys', () => {
    let consoleWarnSpy: jest.SpyInstance;

    beforeEach(() => {
        consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
        jest.clearAllMocks();
        
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);
        jest.spyOn(common, 'findSecretPosition').mockReturnValue({ line: 10, column: 5 });
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(null);
        
        const mockValidateDeepAI = validators as any;
        mockValidateDeepAI.validateDeepAIApiKey.mockResolvedValue({ valid: true });
        
        const mockComputeFingerprint = computeFingerprint as any;
        mockComputeFingerprint.computeFingerprint.mockResolvedValue('deepai-abc12345');
    });

    afterEach(() => {
        consoleWarnSpy.mockRestore();
    });

    test('should return empty array when no matches found', async () => {
        const content = 'const someVariable = "not-an-api-key";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(0);
    });

    test('should detect and validate API key', async () => {
        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect((occurrences[0] as any).secretValue.match.apiKey).toBe('abcd1234-5678-90ab-cdef-123456789012');
        expect(occurrences[0].fingerprint).toBe('deepai-abc12345');
        expect((occurrences[0] as any).type).toBe('API Key');
        expect(occurrences[0].secretType).toBe('DeepAI');
    });

    test('should skip invalid API keys', async () => {
        const mockValidateDeepAI = validators as any;
        mockValidateDeepAI.validateDeepAIApiKey.mockResolvedValue({ valid: false, error: 'Invalid API key' });
        
        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(0);
    });

    test('should skip duplicate API keys', async () => {
        const existingFindings = [{
            fingerprint: "test-fingerprint",
            numOccurrences: 1,
            secretType: "DeepAI",
            validity: "unknown" as const,
            occurrences: new Set(),
            secretValue: {
                someMatch: {
                    match: {
                        apiKey: "abcd1234-5678-90ab-cdef-123456789012"
                    }
                }
            }
        }];
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue(existingFindings as any);
        
        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(0);
    });

    test('should handle multiple unique API keys', async () => {
        const content = `
            const apiKey1 = "abcd1234-5678-90ab-cdef-123456789012";
            const apiKey2 = "efgh5678-90ab-cdef-1234-567890abcdef";
        `;
        const url = 'http://example.com/file.js';

        const mockComputeFingerprint = computeFingerprint as any;
        mockComputeFingerprint.computeFingerprint
            .mockResolvedValueOnce('deepai-abc12345')
            .mockResolvedValueOnce('deepai-def67890');

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(2);
    });

    test('should deduplicate identical API keys', async () => {
        const content = `
            const apiKey1 = "abcd1234-5678-90ab-cdef-123456789012";
            const apiKey2 = "abcd1234-5678-90ab-cdef-123456789012";
        `;
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
    });

    test('should process source map when available', async () => {
        const sourceMapContent = JSON.stringify({
            version: 3,
            sources: ['original.js'],
            names: [],
            mappings: 'AAAA'
        });

        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(new URL('http://example.com/file.js.map'));
        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve(sourceMapContent)
        });

        const mockSourceMapConsumer = {
            initialize: jest.fn(),
            with: jest.fn((content, options, callback) => {
                const mockConsumer = {
                    originalPositionFor: jest.fn().mockReturnValue({
                        source: 'original.js',
                        line: 5,
                        column: 10
                    }),
                    sourceContentFor: jest.fn().mockReturnValue('const originalKey = "abcd1234-5678-90ab-cdef-123456789012";')
                };
                callback(mockConsumer);
            })
        };

        const sourceMap = require('../../../../external/source-map');
        sourceMap.SourceMapConsumer = mockSourceMapConsumer;

        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentFilename).toBe('original.js');
        expect(occurrences[0].sourceContent.content).toBe('const originalKey = "abcd1234-5678-90ab-cdef-123456789012";');
        expect(occurrences[0].sourceContent.contentStartLineNum).toBe(0);
        expect(occurrences[0].sourceContent.contentEndLineNum).toBe(10);
        expect(occurrences[0].sourceContent.exactMatchNumbers).toEqual([5]);
    });

    test('should handle source map fetch error gracefully', async () => {
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(new URL('http://example.com/file.js.map'));
        (global.fetch as jest.Mock).mockRejectedValue(new Error('Source map fetch failed'));

        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentFilename).toBe('file.js');
        expect(occurrences[0].sourceContent.content).toBe(JSON.stringify({
            apiKey: "abcd1234-5678-90ab-cdef-123456789012"
        }));
    });

    test('should handle source map processing when originalPos has no source', async () => {
        const sourceMapContent = JSON.stringify({
            version: 3,
            sources: ['original.js'],
            names: [],
            mappings: 'AAAA'
        });

        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(new URL('http://example.com/file.js.map'));
        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve(sourceMapContent)
        });

        const mockSourceMapConsumer = {
            initialize: jest.fn(),
            with: jest.fn((content, options, callback) => {
                const mockConsumer = {
                    originalPositionFor: jest.fn().mockReturnValue({
                        source: null,
                        line: 5,
                        column: 10
                    }),
                    sourceContentFor: jest.fn()
                };
                callback(mockConsumer);
            })
        };

        const sourceMap = require('../../../../external/source-map');
        sourceMap.SourceMapConsumer = mockSourceMapConsumer;

        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentFilename).toBe('file.js');
        expect(occurrences[0].sourceContent.content).toBe(JSON.stringify({
            apiKey: "abcd1234-5678-90ab-cdef-123456789012"
        }));
    });

    test('should handle existing findings with malformed secretValue', async () => {
        const existingFindings = [{
            fingerprint: "test-fingerprint",
            numOccurrences: 1,
            secretType: "DeepAI",
            validity: "unknown" as const,
            occurrences: new Set(),
            secretValue: {
                someMatch: {
                    match: null // This covers the optional chaining branch
                }
            }
        }];
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue(existingFindings as any);
        
        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1); // Should not be filtered out since match is null
    });

    test('should handle URL without filename path', async () => {
        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/'; // Trailing slash, no filename

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentFilename).toBe(''); // Covers the || "" branch
    });
});