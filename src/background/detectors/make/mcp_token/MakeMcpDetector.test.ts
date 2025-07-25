import { MakeMcpDetector } from './MakeMcpDetector';
import { detectMakeMcpToken } from './make';
import { patterns } from '../../../../config/patterns';

jest.mock('./make');

describe('MakeMcpDetector', () => {
    const mockDetectMakeMcpToken = detectMakeMcpToken as jest.MockedFunction<typeof detectMakeMcpToken>;
    let detector: MakeMcpDetector;

    beforeEach(() => {
        detector = new MakeMcpDetector();
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('interface implementation', () => {
        it('should have correct type property', () => {
            expect(detector.type).toBe('make_mcp');
        });

        it('should have correct name property', () => {
            expect(detector.name).toBe(patterns['Make MCP Token'].familyName);
            expect(detector.name).toBe('Make MCP');
        });

        it('should have readonly type property', () => {
            const originalType = detector.type;
            try {
                (detector as any).type = 'different-type';
                expect(detector.type).toBe(originalType);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });

        it('should have readonly name property', () => {
            const originalName = detector.name;
            try {
                (detector as any).name = 'Different Name';
                expect(detector.name).toBe(originalName);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });
    });

    describe('detect method', () => {
        it('should call detectMakeMcpToken with correct parameters', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            const expectedResult = [
                {
                    secretType: 'Make MCP',
                    fingerprint: 'test-fingerprint',
                    secretValue: {
                        match: {
                            mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                            full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                        }
                    },
                    filePath: 'config.js',
                    url: url,
                    validity: 'valid',
                    sourceContent: {
                        content: '{}',
                        contentFilename: 'config.js',
                        contentStartLineNum: -1,
                        contentEndLineNum: -1,
                        exactMatchNumbers: [-1]
                    }
                }
            ];

            mockDetectMakeMcpToken.mockResolvedValue(expectedResult);

            const result = await detector.detect(content, url);

            expect(mockDetectMakeMcpToken).toHaveBeenCalledWith(content, url);
            expect(mockDetectMakeMcpToken).toHaveBeenCalledTimes(1);
            expect(result).toBe(expectedResult);
        });

        it('should return empty array when no tokens detected', async () => {
            const content = 'const config = { key: "not-a-make-mcp-token" };';
            const url = 'https://example.com/config.js';
            mockDetectMakeMcpToken.mockResolvedValue([]);

            const result = await detector.detect(content, url);

            expect(mockDetectMakeMcpToken).toHaveBeenCalledWith(content, url);
            expect(result).toEqual([]);
        });

        it('should handle multiple occurrences', async () => {
            const content = `
                const url1 = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";
                const url2 = "https://eu1.make.com/api/v1/u/d36fcd27-b5f2-4615-b8d7-d8a581d8d52b/sse";
            `;
            const url = 'https://example.com/config.js';
            const expectedResult = [
                {
                    secretType: 'Make MCP',
                    fingerprint: 'fingerprint-1',
                    secretValue: {
                        match: {
                            mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                            full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                        }
                    },
                    filePath: 'config.js',
                    url: url,
                    validity: 'valid',
                    sourceContent: expect.any(Object)
                },
                {
                    secretType: 'Make MCP',
                    fingerprint: 'fingerprint-2',
                    secretValue: {
                        match: {
                            mcp_token: 'd36fcd27-b5f2-4615-b8d7-d8a581d8d52b',
                            full_url: 'https://eu1.make.com/api/v1/u/d36fcd27-b5f2-4615-b8d7-d8a581d8d52b/sse'
                        }
                    },
                    filePath: 'config.js',
                    url: url,
                    validity: 'valid',
                    sourceContent: expect.any(Object)
                }
            ];

            mockDetectMakeMcpToken.mockResolvedValue(expectedResult);

            const result = await detector.detect(content, url);

            expect(result).toHaveLength(2);
            expect(result).toBe(expectedResult);
        });

        it('should handle empty content', async () => {
            const content = '';
            const url = 'https://example.com/empty.js';
            mockDetectMakeMcpToken.mockResolvedValue([]);

            const result = await detector.detect(content, url);

            expect(mockDetectMakeMcpToken).toHaveBeenCalledWith(content, url);
            expect(result).toEqual([]);
        });

        it('should handle empty URL', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = '';
            const expectedResult = [
                {
                    secretType: 'Make MCP',
                    fingerprint: 'test-fingerprint',
                    secretValue: {
                        match: {
                            mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                            full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                        }
                    },
                    filePath: '',
                    url: '',
                    validity: 'valid',
                    sourceContent: expect.any(Object)
                }
            ];

            mockDetectMakeMcpToken.mockResolvedValue(expectedResult);

            const result = await detector.detect(content, url);

            expect(mockDetectMakeMcpToken).toHaveBeenCalledWith(content, url);
            expect(result).toBe(expectedResult);
        });

        it('should propagate errors from detectMakeMcpToken', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            const error = new Error('Detection failed');
            
            mockDetectMakeMcpToken.mockRejectedValue(error);

            await expect(detector.detect(content, url)).rejects.toThrow('Detection failed');
            expect(mockDetectMakeMcpToken).toHaveBeenCalledWith(content, url);
        });

        it('should handle async operations correctly', async () => {
            const content = 'const mcpUrl = "https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse";';
            const url = 'https://example.com/config.js';
            let resolveDetection: (value: any) => void;
            const detectionPromise = new Promise((resolve) => {
                resolveDetection = resolve;
            });

            mockDetectMakeMcpToken.mockReturnValue(detectionPromise as Promise<any>);

            const detectPromise = detector.detect(content, url);
            
            setTimeout(() => {
                resolveDetection!([{
                    secretType: 'Make MCP',
                    fingerprint: 'async-fingerprint',
                    secretValue: {
                        match: {
                            mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                            full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                        }
                    },
                    filePath: 'config.js',
                    url: url,
                    validity: 'valid',
                    sourceContent: expect.any(Object)
                }]);
            }, 10);

            const result = await detectPromise;

            expect(result).toHaveLength(1);
            expect((result[0].secretValue as any).match.mcp_token).toBe('3b142ebf-e958-4aef-8551-befb27231818');
        });
    });

    describe('constructor', () => {
        it('should create a new instance with correct properties', () => {
            const newDetector = new MakeMcpDetector();
            
            expect(newDetector.type).toBe('make_mcp');
            expect(newDetector.name).toBe('Make MCP');
            expect(typeof newDetector.detect).toBe('function');
        });

        it('should create independent instances', () => {
            const detector1 = new MakeMcpDetector();
            const detector2 = new MakeMcpDetector();
            
            expect(detector1).not.toBe(detector2);
            expect(detector1.type).toBe(detector2.type);
            expect(detector1.name).toBe(detector2.name);
        });
    });

    describe('type compatibility', () => {
        it('should be compatible with SecretDetector interface', () => {
            const secretDetector = detector as any;
            
            expect(typeof secretDetector.type).toBe('string');
            expect(typeof secretDetector.name).toBe('string');
            expect(typeof secretDetector.detect).toBe('function');
        });

        it('should return Promise from detect method', () => {
            const content = 'test content';
            const url = 'test url';
            mockDetectMakeMcpToken.mockResolvedValue([]);

            const result = detector.detect(content, url);

            expect(result).toBeInstanceOf(Promise);
        });
    });
});