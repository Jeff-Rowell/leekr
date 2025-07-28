import { detectMakeMcpToken } from './make';
import { validateMakeMcpToken } from '../../../../utils/validators/make/mcp_token/make';
import { calculateShannonEntropy } from '../../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../../utils/accuracy/falsePositives';
import { 
    findSecretPosition, 
    getExistingFindings, 
    getSourceMapUrl 
} from '../../../../utils/helpers/common';
import { computeFingerprint } from '../../../../utils/helpers/computeFingerprint';
import { patterns } from '../../../../config/patterns';

jest.mock('../../../../utils/validators/make/mcp_token/make');
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

describe('detectMakeMcpToken', () => {
    const mockValidateMakeMcpToken = validateMakeMcpToken as jest.MockedFunction<typeof validateMakeMcpToken>;
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
        mockValidateMakeMcpToken.mockResolvedValue({ valid: true });
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 10 });
        mockGetSourceMapUrl.mockReturnValue(null);
        mockComputeFingerprint.mockResolvedValue('test-fingerprint-hash');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('pattern matching', () => {
        it('should detect valid Make MCP tokens', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0]).toMatchObject({
                secretType: patterns['Make MCP Token'].familyName,
                fingerprint: 'test-fingerprint-hash',
                secretValue: {
                    match: {
                        mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                        full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                    }
                },
                filePath: 'config.js',
                url: url,
                validity: 'valid'
            });
        });

        it('should detect multiple Make MCP tokens', async () => {
            const content = `
                const url1 = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";
                const url2 = "https://eu1.make.com/api/v1/u/d36fcd27-b5f2-4615-b8d7-d8a581d8d52b/sse";
                const url3 = "https://eu2.make.celonis.com/api/v2/u/27627897-f8f1-4215-893c-da95521679c0/sse";
            `;
            const url = 'https://example.com/config.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(3);
            expect((result[0].secretValue as any).match.mcp_token).toBe('3b142ebf-e958-4aef-8551-befb27231818');
            expect((result[1].secretValue as any).match.mcp_token).toBe('d36fcd27-b5f2-4615-b8d7-d8a581d8d52b');
            expect((result[2].secretValue as any).match.mcp_token).toBe('27627897-f8f1-4215-893c-da95521679c0');
        });

        it('should return empty array when no tokens found', async () => {
            const content = 'const config = { apiKey: "not-a-make-mcp-token" };';
            const url = 'https://example.com/config.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
        });

        it('should handle empty content', async () => {
            const content = '';
            const url = 'https://example.com/empty.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
        });

        it('should match different domain variations', async () => {
            const content = `
                "https://eu1.make.com/api/v2/u/3b142ebf-e958-4aef-8551-befb27231818/sse"
                "https://eu2.make.com/api/v2/u/d36fcd27-b5f2-4615-b8d7-d8a581d8d52b/sse"
                "https://us1.make.com/api/v2/u/27627897-f8f1-4215-893c-da95521679c0/sse"
                "https://us2.make.com/api/v2/u/924ee925-f461-466a-99bc-63cfce078057/sse"
                "https://eu1.make.celonis.com/api/v2/u/f71ec344-95f2-4a8c-bda7-3f76f7a6eeea/sse"
                "https://eu2.make.celonis.com/api/v2/u/abc12345-1234-1234-1234-123456789abc/sse"
            `;
            const url = 'https://example.com/config.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(6);
        });
    });

    describe('entropy filtering', () => {
        it('should filter out tokens with low entropy', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockCalculateShannonEntropy.mockReturnValue(-1.0);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
            expect(mockCalculateShannonEntropy).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
        });

        it('should include tokens with sufficient entropy', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockCalculateShannonEntropy.mockReturnValue(4.0);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
        });

        it('should use correct entropy threshold from patterns', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            const entropyThreshold = patterns["Make MCP Token"].entropy;
            mockCalculateShannonEntropy.mockReturnValue(entropyThreshold - 0.1);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
        });
    });

    describe('false positive filtering', () => {
        it('should filter out known false positives', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockIsKnownFalsePositive.mockReturnValue([true, 'test pattern']);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
            expect(mockIsKnownFalsePositive).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
        });

        it('should include tokens that are not false positives', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockIsKnownFalsePositive.mockReturnValue([false, '']);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
        });
    });

    describe('duplicate filtering', () => {
        it('should filter out already found tokens', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockGetExistingFindings.mockResolvedValue([
                {
                    fingerprint: 'existing-fingerprint',
                    secretType: 'Make MCP',
                    secretValue: {
                        match: {
                            mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                            full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                        }
                    },
                    occurrences: new Set(),
                    numOccurrences: 1,
                    validity: 'valid'
                }
            ]);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
        });

        it('should include new tokens not in existing findings', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockGetExistingFindings.mockResolvedValue([
                {
                    fingerprint: 'existing-fingerprint',
                    secretType: 'Make MCP',
                    secretValue: {
                        match: {
                            mcp_token: 'd36fcd27-b5f2-4615-b8d7-d8a581d8d52b',
                            full_url: 'https://eu1.make.com/api/v1/u/d36fcd27-b5f2-4615-b8d7-d8a581d8d52b/sse'
                        }
                    },
                    occurrences: new Set(),
                    numOccurrences: 1,
                    validity: 'valid'
                }
            ]);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
        });

        it('should handle existing findings with secretValue that has no match property', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockGetExistingFindings.mockResolvedValue([
                {
                    fingerprint: 'existing-fingerprint',
                    secretType: 'Make MCP',
                    secretValue: {
                    },
                    occurrences: new Set(),
                    numOccurrences: 1,
                    validity: 'valid'
                }
            ]);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect((result[0].secretValue as any).match.mcp_token).toBe('3b142ebf-e958-4aef-8551-befb27231818');
        });
    });

    describe('validation', () => {
        it('should only include tokens that pass validation', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockValidateMakeMcpToken.mockResolvedValue({ valid: false });

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
        });

        it('should include tokens that pass validation', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockValidateMakeMcpToken.mockResolvedValue({ valid: true });

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect((result[0] as any).validity).toBe('valid');
        });

        it('should handle validation errors gracefully', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockValidateMakeMcpToken.mockResolvedValue({ valid: false, error: 'Network error' });

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
        });
    });

    describe('source mapping', () => {
        it('should handle missing source maps', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockGetSourceMapUrl.mockReturnValue(null);

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].sourceContent).toMatchObject({
                content: JSON.stringify({
                    mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                    full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                }),
                contentFilename: 'config.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            });
        });

        it('should process source maps when available', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
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
                        sourceContentFor: jest.fn().mockReturnValue('const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";')
                    };
                    callback(mockConsumer);
                })
            };

            const sourceMapModule = require('../../../../../external/source-map');
            sourceMapModule.SourceMapConsumer = mockSourceMapConsumer;

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect(mockFetch).toHaveBeenCalledWith(sourceMapUrl);
            expect(mockSourceMapConsumer.initialize).toHaveBeenCalledWith({
                "lib/mappings.wasm": 'chrome-extension://test/libs/mappings.wasm'
            });
            expect(result[0].sourceContent).toMatchObject({
                content: 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";',
                contentFilename: 'src/config.ts',
                contentStartLineNum: 20,
                contentEndLineNum: 30,
                exactMatchNumbers: [25]
            });
        });

        it('should handle source map with no original source', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
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

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].sourceContent).toMatchObject({
                content: JSON.stringify({
                    mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                    full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                }),
                contentFilename: 'config.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            });
        });

        it('should handle source map fetch errors gracefully', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            const sourceMapUrl = new URL('https://example.com/config.js.map');
            
            mockGetSourceMapUrl.mockReturnValue(sourceMapUrl);
            mockFindSecretPosition.mockReturnValue({ line: 10, column: 20 });

            const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
            mockFetch.mockRejectedValue(new Error('Network error'));

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].sourceContent).toMatchObject({
                content: JSON.stringify({
                    mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                    full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                }),
                contentFilename: 'config.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            });
        });

        it('should handle source map processing errors gracefully', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
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

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].sourceContent).toMatchObject({
                content: JSON.stringify({
                    mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                    full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
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
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect(result[0]).toMatchObject({
                secretType: 'Make MCP',
                fingerprint: 'test-fingerprint-hash',
                secretValue: {
                    match: {
                        mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                        full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
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
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';

            await detectMakeMcpToken(content, url);

            expect(mockComputeFingerprint).toHaveBeenCalledWith(
                {
                    match: {
                        mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                        full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                    }
                },
                'SHA-512'
            );
        });

        it('should extract filename from URL correctly', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/path/to/config.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result[0].filePath).toBe('config.js');
        });

        it('should handle URLs without filename', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/';

            const result = await detectMakeMcpToken(content, url);

            expect(result[0].filePath).toBe('');
        });

        it('should extract UUID token correctly from URL', async () => {
            const content = 'const mcpUrl = "https://eu1.make.celonis.com/api/v2/u/abc12345-1234-5678-9abc-123456789def/sse";';
            const url = 'https://example.com/config.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect((result[0].secretValue as any).match.mcp_token).toBe('abc12345-1234-5678-9abc-123456789def');
        });

        it('should handle malformed URLs gracefully', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/invalid-uuid/sse";';
            const url = 'https://example.com/config.js';

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
        });

        it('should handle URLs where UUID extraction fails', async () => {
            // Create a mock URL that passes the pattern but the UUID extraction logic would fail
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';

            // Mock the content.match to return the URL but set up a scenario where the fullUrl doesn't match the UUID regex
            const originalMatch = String.prototype.match;
            let matchCallCount = 0;
            
            String.prototype.match = function(regex: any) {
                matchCallCount++;
                // First call is the pattern match in detectMakeMcpToken (line 12)
                if (matchCallCount === 1) {
                    return ['https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'];
                }
                // Second call is the UUID extraction (line 55) - return null to test the ternary
                if (matchCallCount === 2) {
                    return null;
                }
                return originalMatch.call(this, regex);
            };

            const result = await detectMakeMcpToken(content, url);

            // Restore the original match method
            String.prototype.match = originalMatch;

            expect(result).toHaveLength(1);
            expect(result[0]).toMatchObject({
                secretValue: {
                    match: {
                        mcp_token: '', // Should be empty string when UUID extraction fails
                        full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                    }
                }
            });
        });

    });

    describe('edge cases', () => {
        it('should handle multiple valid tokens with mixed validation results', async () => {
            const content = `
                const url1 = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";
                const url2 = "https://eu1.make.com/api/v1/u/d36fcd27-b5f2-4615-b8d7-d8a581d8d52b/sse";
            `;
            const url = 'https://example.com/config.js';
            
            mockValidateMakeMcpToken
                .mockResolvedValueOnce({ valid: true })
                .mockResolvedValueOnce({ valid: false });

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(1);
            expect((result[0].secretValue as any).match.mcp_token).toBe('3b142ebf-e958-4aef-8551-befb27231818');
        });

        it('should handle validation timeout gracefully', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            mockValidateMakeMcpToken.mockImplementation(() => new Promise(resolve => {
                setTimeout(() => resolve({ valid: false }), 100);
            }));

            const result = await detectMakeMcpToken(content, url);

            expect(result).toHaveLength(0);
        });
    });
});