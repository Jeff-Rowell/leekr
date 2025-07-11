import { DeepAIDetector } from './DeepAIDetector';
import { detectDeepAIKeys } from './deepai';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS } from '../../../utils/accuracy/programmingPatterns';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';
import * as common from '../../../utils/helpers/common';
import { deepaiConfig } from '../../../config/detectors/deepai/deepai';

jest.mock('../../../utils/accuracy/entropy');
jest.mock('../../../utils/accuracy/programmingPatterns', () => ({ COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS: [] }));
jest.mock('../../../utils/accuracy/falsePositives', () => ({ isKnownFalsePositive: jest.fn().mockReturnValue([false, '']) }));
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

const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;

describe('DeepAIDetector', () => {
    let detector: DeepAIDetector;
    let consoleWarnSpy: jest.SpyInstance;

    beforeEach(() => {
        consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
        detector = new DeepAIDetector();
        jest.clearAllMocks();
        
        mockCalculateShannonEntropy.mockReturnValue(4.0);
        
        const mockFalsePositives = require('../../../utils/accuracy/falsePositives');
        mockFalsePositives.isKnownFalsePositive.mockReturnValue([false, '']);
        
        const mockProgrammingPatterns = require('../../../utils/accuracy/programmingPatterns');
        mockProgrammingPatterns.COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.length = 0;
        
        jest.spyOn(common, 'findSecretPosition').mockReturnValue({ line: 10, column: 5 });
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(null);
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);
        
        const mockValidateDeepAI = require('../../../utils/validators/deepai/deepai');
        mockValidateDeepAI.validateDeepAIApiKey.mockResolvedValue({ valid: true });
        
        const mockComputeFingerprint = require('../../../utils/helpers/computeFingerprint');
        mockComputeFingerprint.computeFingerprint.mockResolvedValue('deepai-abc12345');
    });

    afterEach(() => {
        consoleWarnSpy.mockRestore();
    });

    describe('detect', () => {
        test('should detect valid DeepAI API key', async () => {
            const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(1);
            expect(occurrences[0]).toEqual({
                fingerprint: 'deepai-abc12345',
                secretType: "DeepAI",
                filePath: url,
                url: url,
                type: "API Key",
                secretValue: {
                    match: {
                        apiKey: "abcd1234-5678-90ab-cdef-123456789012"
                    }
                },
                sourceContent: {
                    content: JSON.stringify({
                        apiKey: "abcd1234-5678-90ab-cdef-123456789012"
                    }),
                    contentFilename: "file.js",
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                }
            });
        });

        test('should not detect invalid API key with failed validation', async () => {
            const mockValidateDeepAI = require('../../../utils/validators/deepai/deepai');
            mockValidateDeepAI.validateDeepAIApiKey.mockResolvedValue({ valid: false, error: 'Invalid API key' });
            
            const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(0);
        });

        test('should not detect API key with wrong length', async () => {
            const content = 'const apiKey = "abcd1234-5678-90ab";';
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(0);
        });

        test('should not detect API key that is too short', async () => {
            const content = 'const apiKey = "abcd1234-5678-90ab-cdef-12345678901";';
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(0);
        });

        test('should not detect API key when already exists in findings', async () => {
            const existingFindings = [{
                secretValue: {
                    someMatch: {
                        match: {
                            apiKey: "abcd1234-5678-90ab-cdef-123456789012"
                        }
                    }
                }
            }];
            jest.spyOn(common, 'getExistingFindings').mockResolvedValue(existingFindings);
            
            const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(0);
        });

        test('should handle multiple API keys in content', async () => {
            const content = `
                const apiKey1 = "abcd1234-5678-90ab-cdef-123456789012";
                const apiKey2 = "efgh5678-90ab-cdef-1234-567890abcdef";
            `;
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(2);
            expect((occurrences[0].secretValue as any).match.apiKey).toBe("abcd1234-5678-90ab-cdef-123456789012");
            expect((occurrences[1].secretValue as any).match.apiKey).toBe("efgh5678-90ab-cdef-1234-567890abcdef");
        });

        test('should handle content with no API keys', async () => {
            const content = 'const someVariable = "not-an-api-key";';
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(0);
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

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(1);
            expect(occurrences[0].sourceContent.contentFilename).toBe('original.js');
            expect(occurrences[0].sourceContent.content).toBe('const originalKey = "abcd1234-5678-90ab-cdef-123456789012";');
        });

        test('should handle source map processing error gracefully', async () => {
            jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(new URL('http://example.com/file.js.map'));
            (global.fetch as jest.Mock).mockRejectedValue(new Error('Source map fetch failed'));

            const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(1);
            expect(occurrences[0].sourceContent.contentFilename).toBe('file.js');
        });
    });

    describe('properties', () => {
        test('should have correct type and name', () => {
            expect(detector.type).toBe('DeepAI');
            expect(detector.name).toBe('DeepAI');
        });
    });
});

describe('detectDeepAIKeys', () => {
    let consoleWarnSpy: jest.SpyInstance;

    beforeEach(() => {
        consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
        jest.clearAllMocks();
        mockCalculateShannonEntropy.mockReturnValue(4.0);
        
        const mockFalsePositives = require('../../../utils/accuracy/falsePositives');
        mockFalsePositives.isKnownFalsePositive.mockReturnValue([false, '']);
        
        const mockProgrammingPatterns = require('../../../utils/accuracy/programmingPatterns');
        mockProgrammingPatterns.COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.length = 0;
        
        jest.spyOn(common, 'findSecretPosition').mockReturnValue({ line: 10, column: 5 });
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(null);
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);
        
        const mockValidateDeepAI = require('../../../utils/validators/deepai/deepai');
        mockValidateDeepAI.validateDeepAIApiKey.mockResolvedValue({ valid: true });
        
        const mockComputeFingerprint = require('../../../utils/helpers/computeFingerprint');
        mockComputeFingerprint.computeFingerprint.mockResolvedValue('deepai-abc12345');
    });

    afterEach(() => {
        consoleWarnSpy.mockRestore();
    });

    test('should extract correct line numbers for multiline content', async () => {
        const content = `line 1
line 2
const apiKey = "abcd1234-5678-90ab-cdef-123456789012";
line 4`;
        const url = 'http://example.com/file.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentStartLineNum).toBe(-1);
        expect(occurrences[0].sourceContent.contentEndLineNum).toBe(-1);
    });

    test('should extract correct filename from URL', async () => {
        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/path/to/script.js';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentFilename).toBe('script.js');
    });

    test('should handle URL without filename', async () => {
        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        const url = 'http://example.com/';

        const occurrences = await detectDeepAIKeys(content, url);

        expect(occurrences).toHaveLength(1);
        expect(occurrences[0].sourceContent.contentFilename).toBe('');
    });

    test('should generate unique fingerprints for different contexts', async () => {
        const mockComputeFingerprint = require('../../../utils/helpers/computeFingerprint');
        mockComputeFingerprint.computeFingerprint
            .mockResolvedValueOnce('deepai-abc12345')
            .mockResolvedValueOnce('deepai-def67890');
        
        const content = 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";';
        
        const occurrences1 = await detectDeepAIKeys(content, 'http://example.com/file1.js');
        const occurrences2 = await detectDeepAIKeys(content, 'http://example.com/file2.js');

        expect(occurrences1[0].fingerprint).not.toBe(occurrences2[0].fingerprint);
        expect(occurrences1[0].fingerprint).toBe('deepai-abc12345');
        expect(occurrences2[0].fingerprint).toBe('deepai-def67890');
    });

    test('should handle source map processing when available', async () => {
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
});