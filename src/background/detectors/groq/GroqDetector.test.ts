import { GroqDetector } from './GroqDetector';
import { detectGroqKeys } from './groq';

jest.mock('./groq');

const mockDetectGroqKeys = detectGroqKeys as jest.MockedFunction<typeof detectGroqKeys>;

describe('GroqDetector', () => {
    let detector: GroqDetector;

    beforeEach(() => {
        detector = new GroqDetector();
        jest.clearAllMocks();
    });

    it('should have correct type and name', () => {
        expect(detector.type).toBe('Groq');
        expect(detector.name).toBe('Groq API Key Detector');
    });

    it('should call detectGroqKeys with correct parameters', async () => {
        const mockOccurrences = [
            {
                secretType: 'Groq',
                fingerprint: 'test-fingerprint',
                secretValue: { match: { apiKey: 'gsk_' + 'a'.repeat(52) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'API_KEY',
                sourceContent: {
                    content: 'gsk_' + 'a'.repeat(52),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];
        mockDetectGroqKeys.mockResolvedValue(mockOccurrences as any);

        const content = 'const key = "gsk_' + 'a'.repeat(52) + '";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectGroqKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(mockOccurrences);
    });

    it('should return empty array when no occurrences found', async () => {
        mockDetectGroqKeys.mockResolvedValue([]);

        const content = 'const key = "not-a-groq-key";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectGroqKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });

    it('should handle multiple occurrences', async () => {
        const mockOccurrences = [
            {
                secretType: 'Groq',
                fingerprint: 'test-fingerprint-1',
                secretValue: { match: { apiKey: 'gsk_' + 'a'.repeat(52) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'API_KEY',
                sourceContent: {
                    content: 'gsk_' + 'a'.repeat(52),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            },
            {
                secretType: 'Groq',
                fingerprint: 'test-fingerprint-2',
                secretValue: { match: { apiKey: 'gsk_' + 'b'.repeat(52) } },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'API_KEY',
                sourceContent: {
                    content: 'gsk_' + 'b'.repeat(52),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];
        mockDetectGroqKeys.mockResolvedValue(mockOccurrences as any);

        const content = 'const key1 = "gsk_' + 'a'.repeat(52) + '"; const key2 = "gsk_' + 'b'.repeat(52) + '";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectGroqKeys).toHaveBeenCalledWith(content, url);
        expect(result).toHaveLength(2);
        expect(result).toEqual(mockOccurrences);
    });
});