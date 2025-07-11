import { DeepSeekDetector, detectDeepSeekKeys } from './DeepSeekDetector';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS } from '../../../utils/accuracy/programmingPatterns';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';
import * as common from '../../../utils/helpers/common';
import { deepseekConfig } from '../../../config/detectors/deepseek/deepseek';

jest.mock('../../../utils/accuracy/entropy');
jest.mock('../../../utils/accuracy/programmingPatterns', () => ({ COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS: [] }));
jest.mock('../../../utils/accuracy/falsePositives', () => ({ isKnownFalsePositive: jest.fn().mockReturnValue([false, '']) }));
jest.mock('../../../utils/helpers/common');
jest.mock('../../../../external/source-map');

global.fetch = jest.fn();
global.chrome = {
    runtime: {
        getURL: jest.fn((path: string) => `chrome-extension://extension-id/${path}`)
    }
} as any;

const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;

describe('DeepSeekDetector', () => {
    let detector: DeepSeekDetector;

    beforeEach(() => {
        detector = new DeepSeekDetector();
        jest.clearAllMocks();
        
        mockCalculateShannonEntropy.mockReturnValue(4.0);
        
        const mockFalsePositives = require('../../../utils/accuracy/falsePositives');
        mockFalsePositives.isKnownFalsePositive.mockReturnValue([false, '']);
        
        const mockProgrammingPatterns = require('../../../utils/accuracy/programmingPatterns');
        mockProgrammingPatterns.COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.length = 0;
        
        jest.spyOn(common, 'findSecretPosition').mockReturnValue({ line: 10, column: 5 });
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(null);
    });

    describe('detect', () => {
        test('should detect valid DeepSeek API key', async () => {
            const content = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            const url = 'http://example.com/file.js';

            const occurrences = await detector.detect(content, url);

            expect(occurrences).toHaveLength(1);
            expect(occurrences[0]).toEqual({
                fingerprint: expect.stringMatching(/^deepseek-[a-f0-9]{8}$/),
                secretType: 'DeepSeek',
                filePath: 'http://example.com/file.js',
                url: 'http://example.com/file.js',
                type: 'API Key',
                secretValue: {
                    match: {
                        apiKey: 'sk-abcd1234567890abcd1234567890abcd'
                    }
                },
                sourceContent: {
                    content: 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";',
                    contentFilename: 'file.js',
                    contentStartLineNum: 1,
                    contentEndLineNum: 1,
                    exactMatchNumbers: expect.arrayContaining([expect.any(Number), expect.any(Number)])
                }
            });
        });

        test('should not detect invalid API key with wrong prefix', async () => {
            const content = 'const apiKey = "ak-abcd1234567890abcd1234567890abcd";';
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences).toHaveLength(0);
        });

        test('should not detect API key with wrong length', async () => {
            const content = 'const apiKey = "sk-abcd123456789";';
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences).toHaveLength(0);
        });

        test('should not detect API key with low entropy', async () => {
            mockCalculateShannonEntropy.mockReturnValue(3.0);
            const content = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences).toHaveLength(0);
        });

        test('should filter out false positives', async () => {
            const mockModule = require('../../../utils/accuracy/falsePositives');
            mockModule.isKnownFalsePositive.mockReturnValue([true, 'known false positive']);
            
            const content = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences).toHaveLength(0);
        });

        test('should filter out programming patterns', async () => {
            const mockPattern = /test/;
            mockPattern.test = jest.fn().mockReturnValue(true);
            
            const mockModule = require('../../../utils/accuracy/programmingPatterns');
            mockModule.COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.push(mockPattern);
            
            const content = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences).toHaveLength(0);
        });

        test('should detect multiple API keys', async () => {
            const content = `
                const key1 = "sk-abcd1234567890abcd1234567890abcd";
                const key2 = "sk-efgh1234567890efgh1234567890efgh";
            `;
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences).toHaveLength(2);
            expect((occurrences[0].secretValue as any).match.apiKey).toBe('sk-abcd1234567890abcd1234567890abcd');
            expect((occurrences[1].secretValue as any).match.apiKey).toBe('sk-efgh1234567890efgh1234567890efgh');
        });

        test('should handle multiline content correctly', async () => {
            const content = `line 1
line 2
const apiKey = "sk-abcd1234567890abcd1234567890abcd";
line 4`;
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences).toHaveLength(1);
            expect(occurrences[0].sourceContent.contentStartLineNum).toBe(3);
            expect(occurrences[0].sourceContent.contentEndLineNum).toBe(3);
            expect(occurrences[0].sourceContent.content).toBe('const apiKey = "sk-abcd1234567890abcd1234567890abcd";');
        });

        test('should extract filename correctly', async () => {
            const url = 'http://example.com/path/to/test/file.js';
            const content = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            
            const occurrences = await detector.detect(content, url);
            
            expect(occurrences[0].sourceContent.contentFilename).toBe('file.js');
        });

        test('should handle file path without directory', async () => {
            const url = 'http://example.com/file.js';
            const content = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            
            const occurrences = await detector.detect(content, url);
            
            expect(occurrences[0].sourceContent.contentFilename).toBe('file.js');
        });

        test('should generate consistent fingerprints for same content', async () => {
            const content = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            const url = 'http://example.com/test/file.js';
            
            const occurrences1 = await detector.detect(content, url);
            const occurrences2 = await detector.detect(content, url);
            
            expect(occurrences1[0].fingerprint).toBe(occurrences2[0].fingerprint);
        });

        test('should generate different fingerprints for different content', async () => {
            const content1 = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            const content2 = 'const apiKey = "sk-efgh1234567890efgh1234567890efgh";';
            const url = 'http://example.com/test/file.js';
            
            const occurrences1 = await detector.detect(content1, url);
            const occurrences2 = await detector.detect(content2, url);
            
            expect(occurrences1[0].fingerprint).not.toBe(occurrences2[0].fingerprint);
        });

        test('should set correct exactMatchNumbers', async () => {
            const content = 'prefix sk-abcd1234567890abcd1234567890abcd suffix';
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences[0].sourceContent.exactMatchNumbers).toEqual([7, 42]);
        });

        test('should handle content at line boundaries', async () => {
            const content = 'sk-abcd1234567890abcd1234567890abcd';
            
            const occurrences = await detector.detect(content, 'http://example.com');
            
            expect(occurrences).toHaveLength(1);
            expect(occurrences[0].sourceContent.content).toBe('sk-abcd1234567890abcd1234567890abcd');
        });

        test('should not modify detector state between calls', async () => {
            const content1 = 'const key1 = "sk-abcd1234567890abcd1234567890abcd";';
            const content2 = 'const key2 = "sk-efgh1234567890efgh1234567890efgh";';
            
            const occurrences1 = await detector.detect(content1, 'http://example.com/1');
            const occurrences2 = await detector.detect(content2, 'http://example.com/2');
            
            expect(occurrences1).toHaveLength(1);
            expect(occurrences2).toHaveLength(1);
            expect((occurrences1[0].secretValue as any).match.apiKey).toBe('sk-abcd1234567890abcd1234567890abcd');
            expect((occurrences2[0].secretValue as any).match.apiKey).toBe('sk-efgh1234567890efgh1234567890efgh');
        });

        test('should handle source map processing', async () => {
            const mockSourceMapUrl = new URL('http://example.com/app.js.map');
            const mockSourceMapContent = '{"version":3,"sources":["src/app.js"],"mappings":"AAAA"}';
            const mockOriginalSource = 'const deepSeekKey = "sk-abcd1234567890abcd1234567890abcd";';
            
            jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(mockSourceMapUrl);
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

            const content = 'var t="sk-abcd1234567890abcd1234567890abcd";';
            const occurrences = await detector.detect(content, 'http://example.com/bundle.js');

            expect(occurrences).toHaveLength(1);
            expect(occurrences[0].sourceContent.contentFilename).toBe('src/app.js');
            expect(occurrences[0].sourceContent.content).toBe(mockOriginalSource);
            expect(occurrences[0].sourceContent.exactMatchNumbers).toEqual([1]);
        });

        test('should fallback gracefully when source map processing fails', async () => {
            const mockSourceMapUrl = new URL('http://example.com/app.js.map');
            const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
            
            jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(mockSourceMapUrl);
            (global.fetch as jest.Mock).mockRejectedValue(new Error('Failed to fetch source map'));

            const content = 'var t="sk-abcd1234567890abcd1234567890abcd";';
            const occurrences = await detector.detect(content, 'http://example.com/bundle.js');

            expect(occurrences).toHaveLength(1);
            expect(occurrences[0].sourceContent.contentFilename).toBe('bundle.js');
            expect(occurrences[0].sourceContent.content).toBe('var t="sk-abcd1234567890abcd1234567890abcd";');
            
            consoleWarnSpy.mockRestore();
        });

        test('should not detect API key that matches regex but fails validation', async () => {
            // Test edge case where regex matches but validation fails
            // Create a scenario where the API key has correct format but wrong length somehow
            const originalExec = RegExp.prototype.exec;
            const mockPattern = deepseekConfig.patterns.apiKey.pattern;
            
            // Mock the regex to return a match that would fail isValidApiKey
            jest.spyOn(mockPattern, 'exec').mockImplementationOnce(() => {
                const result = ['sk-invalidlength', 'sk-invalidlength'] as any;
                result.index = 0;
                return result;
            }).mockImplementationOnce(() => null);

            const content = 'const apiKey = "sk-invalidlength";';
            const occurrences = await detector.detect(content, 'http://example.com');

            expect(occurrences).toHaveLength(0);
            
            // Restore original exec
            mockPattern.exec = originalExec;
        });

        test('should handle edge case in filename extraction', async () => {
            // Test edge case where URL has no slashes or pop() could return undefined
            const content = 'const apiKey = "sk-abcd1234567890abcd1234567890abcd";';
            const url = '';
            
            const occurrences = await detector.detect(content, url);
            
            expect(occurrences).toHaveLength(1);
            expect(occurrences[0].sourceContent.contentFilename).toBe('');
        });
    });

    describe('detector properties', () => {
        test('should have correct detector properties', () => {
            expect(detector.name).toBe('DeepSeek');
            expect(detector.type).toBe('DeepSeek');
        });
    });
});