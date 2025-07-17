import { RapidApiDetector } from './RapidApiDetector';
import { detectRapidApiKeys } from './rapid_api';

jest.mock('./rapid_api');

const mockDetectRapidApiKeys = detectRapidApiKeys as jest.MockedFunction<typeof detectRapidApiKeys>;

describe('RapidApiDetector', () => {
    let detector: RapidApiDetector;

    beforeEach(() => {
        detector = new RapidApiDetector();
        jest.clearAllMocks();
    });

    it('should have correct type and name', () => {
        expect(detector.type).toBe('rapid_api');
        expect(detector.name).toBe('RapidAPI');
    });

    it('should call detectRapidApiKeys when detect is called', async () => {
        const content = 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789012";';
        const url = 'https://example.com/test.js';
        const expectedResult = [
            {
                secretType: 'RapidAPI',
                fingerprint: 'test-fingerprint',
                secretValue: {
                    match: {
                        api_key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789012'
                    }
                },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'API Key',
                sourceContent: {
                    content: JSON.stringify({
                        api_key: 'abcdefghij1234567890ABCDEFGHIJ1234567890123456789012'
                    }),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];

        mockDetectRapidApiKeys.mockResolvedValue(expectedResult);

        const result = await detector.detect(content, url);

        expect(mockDetectRapidApiKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(expectedResult);
    });

    it('should return empty array when no keys are detected', async () => {
        const content = 'const config = { apiKey: "not-a-rapidapi-key" };';
        const url = 'https://example.com/test.js';

        mockDetectRapidApiKeys.mockResolvedValue([]);

        const result = await detector.detect(content, url);

        expect(mockDetectRapidApiKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });
});