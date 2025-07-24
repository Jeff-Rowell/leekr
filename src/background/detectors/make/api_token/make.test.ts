import { detectMakeApiToken } from './make';
import { validateMakeApiToken } from '../../../../utils/validators/make/api_token/make';
import { calculateShannonEntropy } from '../../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../../utils/accuracy/falsePositives';
import { 
    findSecretPosition, 
    getExistingFindings, 
    getSourceMapUrl 
} from '../../../../utils/helpers/common';
import { computeFingerprint } from '../../../../utils/helpers/computeFingerprint';
import { patterns } from '../../../../config/patterns';

jest.mock('../../../../utils/validators/make/api_token/make');
jest.mock('../../../../utils/accuracy/entropy');
jest.mock('../../../../utils/accuracy/falsePositives');
jest.mock('../../../../utils/helpers/common');
jest.mock('../../../../utils/helpers/computeFingerprint');
jest.mock('../../../../../external/source-map');

global.fetch = jest.fn();
global.chrome = {
    runtime: {
        getURL: jest.fn().mockReturnValue('chrome-extension://test/libs/mappings.wasm')
    }
} as any;

describe('detectMakeApiToken', () => {
    const mockValidateMakeApiToken = validateMakeApiToken as jest.MockedFunction<typeof validateMakeApiToken>;
    const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;
    const mockIsKnownFalsePositive = isKnownFalsePositive as jest.MockedFunction<typeof isKnownFalsePositive>;
    const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
    const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
    const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
    const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

    beforeEach(() => {
        jest.clearAllMocks();
        mockCalculateShannonEntropy.mockReturnValue(4.0);
        mockIsKnownFalsePositive.mockReturnValue([false, '']);
        mockGetExistingFindings.mockResolvedValue([]);
        mockValidateMakeApiToken.mockResolvedValue({ valid: true });
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 10 });
        mockGetSourceMapUrl.mockReturnValue(null);
        mockComputeFingerprint.mockResolvedValue('test-fingerprint-hash');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('pattern matching', () => {
        it('should detect valid Make API tokens', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0]).toMatchObject({
                secretType: patterns['Make API Token'].familyName,
                fingerprint: 'test-fingerprint-hash',
                secretValue: {
                    match: {
                        api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                    }
                },
                filePath: 'config.js',
                url: url,
                validity: 'valid'
            });
        });

        it('should detect multiple Make API tokens', async () => {
            const content = `
                const token1 = "bbb49d50-239a-4609-9569-63ea15ef0997";
                const token2 = "924ee925-f461-466a-99bc-63cfce078057";
                const token3 = "f71ec344-95f2-4a8c-bda7-3f76f7a6eeea";
            `;
            const url = 'https://example.com/config.js';

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(3);
            expect((result[0].secretValue as any).match.api_token).toBe('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect((result[1].secretValue as any).match.api_token).toBe('924ee925-f461-466a-99bc-63cfce078057');
            expect((result[2].secretValue as any).match.api_token).toBe('f71ec344-95f2-4a8c-bda7-3f76f7a6eeea');
        });

        it('should return empty array when no tokens found', async () => {
            const content = 'const config = { apiKey: "not-a-make-token" };';
            const url = 'https://example.com/config.js';

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
        });

        it('should handle empty content', async () => {
            const content = '';
            const url = 'https://example.com/empty.js';

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
        });
    });

    describe('entropy filtering', () => {
        it('should filter out tokens with low entropy', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockCalculateShannonEntropy.mockReturnValue(2.0);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
            expect(mockCalculateShannonEntropy).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
        });

        it('should include tokens with sufficient entropy', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockCalculateShannonEntropy.mockReturnValue(4.0);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
        });

        it('should use correct entropy threshold from patterns', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            const entropyThreshold = patterns["Make API Token"].entropy;
            mockCalculateShannonEntropy.mockReturnValue(entropyThreshold - 0.1);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
        });
    });

    describe('false positive filtering', () => {
        it('should filter out known false positives', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockIsKnownFalsePositive.mockReturnValue([true, 'test pattern']);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
            expect(mockIsKnownFalsePositive).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
        });

        it('should include tokens that are not false positives', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockIsKnownFalsePositive.mockReturnValue([false, '']);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
        });
    });

    describe('duplicate filtering', () => {
        it('should filter out already found tokens', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockGetExistingFindings.mockResolvedValue([
                {
                    fingerprint: 'existing-fingerprint',
                    secretType: 'Make',
                    secretValue: {
                        match: {
                            api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                        }
                    },
                    occurrences: new Set(),
                    numOccurrences: 1,
                    validity: 'valid'
                }
            ]);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
        });

        it('should include new tokens not in existing findings', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockGetExistingFindings.mockResolvedValue([
                {
                    fingerprint: 'existing-fingerprint',
                    secretType: 'Make',
                    secretValue: {
                        match: {
                            api_token: 'different-token-here'
                        }
                    },
                    occurrences: new Set(),
                    numOccurrences: 1,
                    validity: 'valid'
                }
            ]);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
        });

        it('should handle existing findings with secretValue that has no match property', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockGetExistingFindings.mockResolvedValue([
                {
                    fingerprint: 'existing-fingerprint',
                    secretType: 'Make',
                    secretValue: {
                        // No match property
                    },
                    occurrences: new Set(),
                    numOccurrences: 1,
                    validity: 'valid'
                }
            ]);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect((result[0].secretValue as any).match.api_token).toBe('bbb49d50-239a-4609-9569-63ea15ef0997');
        });
    });

    describe('validation', () => {
        it('should only include tokens that pass validation', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockValidateMakeApiToken.mockResolvedValue({ valid: false });

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
        });

        it('should include tokens that pass validation', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect((result[0] as any).validity).toBe('valid');
        });

        it('should handle validation errors gracefully', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockValidateMakeApiToken.mockResolvedValue({ valid: false, error: 'Network error' });

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
        });
    });

    describe('source mapping', () => {
        it('should handle missing source maps', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockGetSourceMapUrl.mockReturnValue(null);

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].sourceContent).toMatchObject({
                content: JSON.stringify({
                    api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                }),
                contentFilename: 'config.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            });
        });

        it('should process source maps when available', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            const sourceMapUrl = new URL('https://example.com/config.js.map');
            
            mockGetSourceMapUrl.mockReturnValue(sourceMapUrl);
            mockFindSecretPosition.mockReturnValue({ line: 10, column: 20 });

            const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
            mockFetch.mockResolvedValue({
                text: jest.fn().mockResolvedValue('{"version":3,"sources":["src/config.ts"],"mappings":"AAAA"}')
            } as any);

            const mockSourceMapConsumer = {
                initialize: jest.fn(),
                with: jest.fn().mockImplementation((content, options, callback) => {
                    const mockConsumer = {
                        originalPositionFor: jest.fn().mockReturnValue({
                            source: 'src/config.ts',
                            line: 25,
                            column: 15
                        }),
                        sourceContentFor: jest.fn().mockReturnValue('const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";')
                    };
                    callback(mockConsumer);
                })
            };

            const sourceMapModule = require('../../../../../external/source-map');
            sourceMapModule.SourceMapConsumer = mockSourceMapConsumer;

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect(mockFetch).toHaveBeenCalledWith(sourceMapUrl);
            expect(mockSourceMapConsumer.initialize).toHaveBeenCalledWith({
                "lib/mappings.wasm": 'chrome-extension://test/libs/mappings.wasm'
            });
            expect(result[0].sourceContent).toMatchObject({
                content: 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";',
                contentFilename: 'src/config.ts',
                contentStartLineNum: 20,
                contentEndLineNum: 30,
                exactMatchNumbers: [25]
            });
        });

        it('should handle source map with no original source', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            const sourceMapUrl = new URL('https://example.com/config.js.map');
            
            mockGetSourceMapUrl.mockReturnValue(sourceMapUrl);
            mockFindSecretPosition.mockReturnValue({ line: 10, column: 20 });

            const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
            mockFetch.mockResolvedValue({
                text: jest.fn().mockResolvedValue('{"version":3,"sources":[],"mappings":""}')
            } as any);

            const mockSourceMapConsumer = {
                initialize: jest.fn(),
                with: jest.fn().mockImplementation((content, options, callback) => {
                    const mockConsumer = {
                        originalPositionFor: jest.fn().mockReturnValue({
                            source: null,
                            line: null,
                            column: null
                        }),
                        sourceContentFor: jest.fn()
                    };
                    callback(mockConsumer);
                })
            };

            const sourceMapModule = require('../../../../../external/source-map');
            sourceMapModule.SourceMapConsumer = mockSourceMapConsumer;

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].sourceContent).toMatchObject({
                content: JSON.stringify({
                    api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                }),
                contentFilename: 'config.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            });
        });

        it('should handle source map fetch errors gracefully', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            const sourceMapUrl = new URL('https://example.com/config.js.map');
            
            mockGetSourceMapUrl.mockReturnValue(sourceMapUrl);
            mockFindSecretPosition.mockReturnValue({ line: 10, column: 20 });

            const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
            mockFetch.mockRejectedValue(new Error('Network error'));

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].sourceContent).toMatchObject({
                content: JSON.stringify({
                    api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                }),
                contentFilename: 'config.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            });
        });

        it('should handle source map processing errors gracefully', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            const sourceMapUrl = new URL('https://example.com/config.js.map');
            
            mockGetSourceMapUrl.mockReturnValue(sourceMapUrl);
            mockFindSecretPosition.mockReturnValue({ line: 10, column: 20 });

            const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
            mockFetch.mockResolvedValue({
                text: jest.fn().mockResolvedValue('invalid json')
            } as any);

            const mockSourceMapConsumer = {
                initialize: jest.fn(),
                with: jest.fn().mockImplementation(() => {
                    throw new Error('Source map parsing error');
                })
            };

            const sourceMapModule = require('../../../../../external/source-map');
            sourceMapModule.SourceMapConsumer = mockSourceMapConsumer;

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].sourceContent).toMatchObject({
                content: JSON.stringify({
                    api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                }),
                contentFilename: 'config.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            });
        });
    });

    describe('result structure', () => {
        it('should return properly structured occurrence objects', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0]).toMatchObject({
                secretType: 'Make',
                fingerprint: 'test-fingerprint-hash',
                secretValue: {
                    match: {
                        api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                    }
                },
                filePath: 'config.js',
                url: 'https://example.com/config.js',
                validity: 'valid',
                sourceContent: expect.objectContaining({
                    content: expect.any(String),
                    contentFilename: expect.any(String),
                    contentStartLineNum: expect.any(Number),
                    contentEndLineNum: expect.any(Number),
                    exactMatchNumbers: expect.any(Array)
                })
            });
        });

        it('should compute fingerprint correctly', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';

            await detectMakeApiToken(content, url);

            expect(mockComputeFingerprint).toHaveBeenCalledWith(
                {
                    match: {
                        api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                    }
                },
                'SHA-512'
            );
        });

        it('should extract filename from URL correctly', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/path/to/config.js';

            const result = await detectMakeApiToken(content, url);

            expect(result[0].filePath).toBe('config.js');
        });

        it('should handle URLs without filename', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/';

            const result = await detectMakeApiToken(content, url);

            expect(result[0].filePath).toBe('');
        });
    });

    describe('edge cases', () => {
        it('should handle multiple valid tokens with mixed validation results', async () => {
            const content = `
                const token1 = "bbb49d50-239a-4609-9569-63ea15ef0997";
                const token2 = "924ee925-f461-466a-99bc-63cfce078057";
            `;
            const url = 'https://example.com/config.js';
            
            mockValidateMakeApiToken
                .mockResolvedValueOnce({ valid: true })
                .mockResolvedValueOnce({ valid: false });

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(1);
            expect((result[0].secretValue as any).match.api_token).toBe('bbb49d50-239a-4609-9569-63ea15ef0997');
        });

        it('should handle validation timeout gracefully', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            mockValidateMakeApiToken.mockImplementation(() => new Promise(resolve => {
                setTimeout(() => resolve({ valid: false }), 100);
            }));

            const result = await detectMakeApiToken(content, url);

            expect(result).toHaveLength(0);
        });
    });
});