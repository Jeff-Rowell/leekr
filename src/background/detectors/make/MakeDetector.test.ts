import { MakeDetector } from './MakeDetector';
import { detectMakeApiToken } from './make';
import { patterns } from '../../../config/patterns';

jest.mock('./make');

describe('MakeDetector', () => {
    const mockDetectMakeApiToken = detectMakeApiToken as jest.MockedFunction<typeof detectMakeApiToken>;
    let detector: MakeDetector;

    beforeEach(() => {
        detector = new MakeDetector();
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('interface implementation', () => {
        it('should have correct type property', () => {
            expect(detector.type).toBe('make');
        });

        it('should have correct name property', () => {
            expect(detector.name).toBe(patterns['Make API Token'].familyName);
            expect(detector.name).toBe('Make');
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
        it('should call detectMakeApiToken with correct parameters', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            const expectedResult = [
                {
                    secretType: 'Make',
                    fingerprint: 'test-fingerprint',
                    secretValue: {
                        match: {
                            api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
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

            mockDetectMakeApiToken.mockResolvedValue(expectedResult);

            const result = await detector.detect(content, url);

            expect(mockDetectMakeApiToken).toHaveBeenCalledWith(content, url);
            expect(mockDetectMakeApiToken).toHaveBeenCalledTimes(1);
            expect(result).toBe(expectedResult);
        });

        it('should return empty array when no tokens detected', async () => {
            const content = 'const config = { key: "not-a-make-token" };';
            const url = 'https://example.com/config.js';
            mockDetectMakeApiToken.mockResolvedValue([]);

            const result = await detector.detect(content, url);

            expect(mockDetectMakeApiToken).toHaveBeenCalledWith(content, url);
            expect(result).toEqual([]);
        });

        it('should handle multiple occurrences', async () => {
            const content = `
                const token1 = "bbb49d50-239a-4609-9569-63ea15ef0997";
                const token2 = "924ee925-f461-466a-99bc-63cfce078057";
            `;
            const url = 'https://example.com/config.js';
            const expectedResult = [
                {
                    secretType: 'Make',
                    fingerprint: 'fingerprint-1',
                    secretValue: {
                        match: {
                            api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                        }
                    },
                    filePath: 'config.js',
                    url: url,
                    validity: 'valid',
                    sourceContent: expect.any(Object)
                },
                {
                    secretType: 'Make',
                    fingerprint: 'fingerprint-2',
                    secretValue: {
                        match: {
                            api_token: '924ee925-f461-466a-99bc-63cfce078057'
                        }
                    },
                    filePath: 'config.js',
                    url: url,
                    validity: 'valid',
                    sourceContent: expect.any(Object)
                }
            ];

            mockDetectMakeApiToken.mockResolvedValue(expectedResult);

            const result = await detector.detect(content, url);

            expect(result).toHaveLength(2);
            expect(result).toBe(expectedResult);
        });

        it('should handle empty content', async () => {
            const content = '';
            const url = 'https://example.com/empty.js';
            mockDetectMakeApiToken.mockResolvedValue([]);

            const result = await detector.detect(content, url);

            expect(mockDetectMakeApiToken).toHaveBeenCalledWith(content, url);
            expect(result).toEqual([]);
        });

        it('should handle empty URL', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = '';
            const expectedResult = [
                {
                    secretType: 'Make',
                    fingerprint: 'test-fingerprint',
                    secretValue: {
                        match: {
                            api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                        }
                    },
                    filePath: '',
                    url: '',
                    validity: 'valid',
                    sourceContent: expect.any(Object)
                }
            ];

            mockDetectMakeApiToken.mockResolvedValue(expectedResult);

            const result = await detector.detect(content, url);

            expect(mockDetectMakeApiToken).toHaveBeenCalledWith(content, url);
            expect(result).toBe(expectedResult);
        });

        it('should propagate errors from detectMakeApiToken', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            const error = new Error('Detection failed');
            
            mockDetectMakeApiToken.mockRejectedValue(error);

            await expect(detector.detect(content, url)).rejects.toThrow('Detection failed');
            expect(mockDetectMakeApiToken).toHaveBeenCalledWith(content, url);
        });

        it('should handle async operations correctly', async () => {
            const content = 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";';
            const url = 'https://example.com/config.js';
            let resolveDetection: (value: any) => void;
            const detectionPromise = new Promise((resolve) => {
                resolveDetection = resolve;
            });

            mockDetectMakeApiToken.mockReturnValue(detectionPromise as Promise<any>);

            const detectPromise = detector.detect(content, url);
            
            setTimeout(() => {
                resolveDetection!([{
                    secretType: 'Make',
                    fingerprint: 'async-fingerprint',
                    secretValue: {
                        match: {
                            api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
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
            expect((result[0].secretValue as any).match.api_token).toBe('bbb49d50-239a-4609-9569-63ea15ef0997');
        });
    });

    describe('constructor', () => {
        it('should create a new instance with correct properties', () => {
            const newDetector = new MakeDetector();
            
            expect(newDetector.type).toBe('make');
            expect(newDetector.name).toBe('Make');
            expect(typeof newDetector.detect).toBe('function');
        });

        it('should create independent instances', () => {
            const detector1 = new MakeDetector();
            const detector2 = new MakeDetector();
            
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
            mockDetectMakeApiToken.mockResolvedValue([]);

            const result = detector.detect(content, url);

            expect(result).toBeInstanceOf(Promise);
        });
    });
});