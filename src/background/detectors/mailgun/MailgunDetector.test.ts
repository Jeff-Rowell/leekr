import { MailgunDetector } from './MailgunDetector';
import { detectMailgunKeys } from './mailgun';

jest.mock('./mailgun');

const mockDetectMailgunKeys = detectMailgunKeys as jest.MockedFunction<typeof detectMailgunKeys>;

describe('MailgunDetector', () => {
    let detector: MailgunDetector;

    beforeEach(() => {
        detector = new MailgunDetector();
        jest.clearAllMocks();
    });

    it('should have correct type and name', () => {
        expect(detector.type).toBe('Mailgun');
        expect(detector.name).toBe('Mailgun');
    });

    it('should call detectMailgunKeys with correct parameters', async () => {
        const mockOccurrences = [
            {
                secretType: 'Mailgun',
                fingerprint: 'test-fingerprint',
                secretValue: { match: { apiKey: 'key-' + 'a'.repeat(32) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'Mailgun API Key',
                sourceContent: {
                    content: 'key-' + 'a'.repeat(32),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];
        mockDetectMailgunKeys.mockResolvedValue(mockOccurrences as any);

        const content = 'const key = "key-' + 'a'.repeat(32) + '";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectMailgunKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(mockOccurrences);
    });

    it('should return empty array when no occurrences found', async () => {
        mockDetectMailgunKeys.mockResolvedValue([]);

        const content = 'const key = "not-a-mailgun-key";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectMailgunKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });

    it('should handle multiple occurrences', async () => {
        const mockOccurrences = [
            {
                secretType: 'Mailgun',
                fingerprint: 'test-fingerprint-1',
                secretValue: { match: { apiKey: 'key-' + 'a'.repeat(32) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'Mailgun API Key',
                sourceContent: {
                    content: 'key-' + 'a'.repeat(32),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            },
            {
                secretType: 'Mailgun',
                fingerprint: 'test-fingerprint-2',
                secretValue: { match: { apiKey: 'b'.repeat(72) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'Mailgun API Key',
                sourceContent: {
                    content: 'b'.repeat(72),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];
        mockDetectMailgunKeys.mockResolvedValue(mockOccurrences as any);

        const content = 'const key1 = "key-' + 'a'.repeat(32) + '"; const key2 = "' + 'b'.repeat(72) + '";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectMailgunKeys).toHaveBeenCalledWith(content, url);
        expect(result).toHaveLength(2);
        expect(result).toEqual(mockOccurrences);
    });

    it('should handle different Mailgun token formats', async () => {
        const mockOccurrences = [
            {
                secretType: 'Mailgun',
                fingerprint: 'test-fingerprint-original',
                secretValue: { match: { apiKey: 'a'.repeat(72) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'Mailgun API Key',
                sourceContent: {
                    content: 'a'.repeat(72),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            },
            {
                secretType: 'Mailgun',
                fingerprint: 'test-fingerprint-key',
                secretValue: { match: { apiKey: 'key-' + 'b'.repeat(32) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'Mailgun API Key',
                sourceContent: {
                    content: 'key-' + 'b'.repeat(32),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            },
            {
                secretType: 'Mailgun',
                fingerprint: 'test-fingerprint-hex',
                secretValue: { match: { apiKey: 'c'.repeat(32) + '-' + 'd'.repeat(8) + '-' + 'e'.repeat(8) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'Mailgun API Key',
                sourceContent: {
                    content: 'c'.repeat(32) + '-' + 'd'.repeat(8) + '-' + 'e'.repeat(8),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];
        mockDetectMailgunKeys.mockResolvedValue(mockOccurrences as any);

        const content = 'const original = "' + 'a'.repeat(72) + '"; const keyFormat = "key-' + 'b'.repeat(32) + '"; const hexFormat = "' + 'c'.repeat(32) + '-' + 'd'.repeat(8) + '-' + 'e'.repeat(8) + '";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectMailgunKeys).toHaveBeenCalledWith(content, url);
        expect(result).toHaveLength(3);
        expect(result).toEqual(mockOccurrences);
    });
});