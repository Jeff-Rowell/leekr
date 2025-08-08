import { PayPalOAuthDetector } from './PayPalOAuthDetector';
import { detectPayPalOAuth } from './paypal_oauth';
import { patterns } from '../../../config/patterns';

jest.mock('./paypal_oauth');

const mockDetectPayPalOAuth = detectPayPalOAuth as jest.MockedFunction<typeof detectPayPalOAuth>;

describe('PayPalOAuthDetector', () => {
    let detector: PayPalOAuthDetector;

    beforeEach(() => {
        detector = new PayPalOAuthDetector();
        jest.clearAllMocks();
    });

    describe('constructor', () => {
        it('should have correct type', () => {
            expect(detector.type).toBe('paypal_oauth');
        });

        it('should have correct name from patterns', () => {
            expect(detector.name).toBe(patterns['PayPal OAuth Client Secret'].familyName);
        });
    });

    describe('detect', () => {
        it('should call detectPayPalOAuth with correct parameters', async () => {
            const content = 'test content';
            const url = 'https://example.com/test.js';
            const expectedResult = [
                {
                    secretType: 'PayPal OAuth',
                    fingerprint: 'test-fingerprint',
                    secretValue: {
                        match: {
                            client_id: 'test-client-id',
                            client_secret: 'test-client-secret'
                        }
                    },
                    filePath: 'test.js',
                    url: 'https://example.com/test.js',
                    validity: 'valid',
                    sourceContent: {
                        content: 'test source content',
                        contentFilename: 'test.js',
                        contentStartLineNum: 1,
                        contentEndLineNum: 10,
                        exactMatchNumbers: [5]
                    }
                }
            ];

            mockDetectPayPalOAuth.mockResolvedValue(expectedResult);

            const result = await detector.detect(content, url);

            expect(mockDetectPayPalOAuth).toHaveBeenCalledWith(content, url);
            expect(result).toBe(expectedResult);
        });

        it('should return empty array when no occurrences found', async () => {
            const content = 'no paypal credentials here';
            const url = 'https://example.com/test.js';

            mockDetectPayPalOAuth.mockResolvedValue([]);

            const result = await detector.detect(content, url);

            expect(mockDetectPayPalOAuth).toHaveBeenCalledWith(content, url);
            expect(result).toEqual([]);
        });

        it('should pass through multiple occurrences', async () => {
            const content = 'multiple paypal credentials';
            const url = 'https://example.com/test.js';
            const expectedResult = [
                {
                    secretType: 'PayPal OAuth',
                    fingerprint: 'test-fingerprint-1',
                    secretValue: {
                        match: {
                            client_id: 'test-client-id-1',
                            client_secret: 'test-client-secret-1'
                        }
                    },
                    filePath: 'test.js',
                    url: 'https://example.com/test.js',
                    validity: 'valid',
                    sourceContent: {
                        content: 'test source content',
                        contentFilename: 'test.js',
                        contentStartLineNum: 1,
                        contentEndLineNum: 10,
                        exactMatchNumbers: [5]
                    }
                },
                {
                    secretType: 'PayPal OAuth',
                    fingerprint: 'test-fingerprint-2',
                    secretValue: {
                        match: {
                            client_id: 'test-client-id-2',
                            client_secret: 'test-client-secret-2'
                        }
                    },
                    filePath: 'test.js',
                    url: 'https://example.com/test.js',
                    validity: 'valid',
                    sourceContent: {
                        content: 'test source content',
                        contentFilename: 'test.js',
                        contentStartLineNum: 1,
                        contentEndLineNum: 10,
                        exactMatchNumbers: [8]
                    }
                }
            ];

            mockDetectPayPalOAuth.mockResolvedValue(expectedResult);

            const result = await detector.detect(content, url);

            expect(mockDetectPayPalOAuth).toHaveBeenCalledWith(content, url);
            expect(result).toBe(expectedResult);
        });
    });
});