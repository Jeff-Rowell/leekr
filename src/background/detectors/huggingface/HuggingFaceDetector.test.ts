import { HuggingFaceDetector } from './HuggingFaceDetector';
import { detectHuggingFaceKeys } from './huggingface';
import { Occurrence } from '../../../types/findings.types';

jest.mock('./huggingface');

const mockDetectHuggingFaceKeys = detectHuggingFaceKeys as jest.MockedFunction<typeof detectHuggingFaceKeys>;

describe('HuggingFaceDetector', () => {
    let detector: HuggingFaceDetector;

    beforeEach(() => {
        detector = new HuggingFaceDetector();
        jest.clearAllMocks();
    });

    test('has correct type', () => {
        expect(detector.type).toBe('Hugging Face');
    });

    test('calls detectHuggingFaceKeys with correct parameters', async () => {
        const mockOccurrences: Occurrence[] = [
            {
                filePath: 'test.js',
                fingerprint: 'test-fp',
                secretType: 'Hugging Face',
                secretValue: { match: { api_key: 'hf_test123' } },
                sourceContent: {
                    content: 'test content',
                    contentFilename: 'test.js',
                    contentStartLineNum: 1,
                    contentEndLineNum: 5,
                    exactMatchNumbers: [2]
                },
                url: 'https://example.com/test.js'
            }
        ];

        mockDetectHuggingFaceKeys.mockResolvedValue(mockOccurrences);

        const content = 'const key = "hf_1234567890abcdefghijklmnopqrstuv12";';
        const url = 'https://example.com/app.js';

        const result = await detector.detect(content, url);

        expect(mockDetectHuggingFaceKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(mockOccurrences);
    });

    test('returns empty array when no keys detected', async () => {
        mockDetectHuggingFaceKeys.mockResolvedValue([]);

        const content = 'const config = { other: "value" };';
        const url = 'https://example.com/app.js';

        const result = await detector.detect(content, url);

        expect(mockDetectHuggingFaceKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });

    test('propagates errors from detectHuggingFaceKeys', async () => {
        const error = new Error('Detection failed');
        mockDetectHuggingFaceKeys.mockRejectedValue(error);

        const content = 'const key = "hf_test123";';
        const url = 'https://example.com/app.js';

        await expect(detector.detect(content, url)).rejects.toThrow('Detection failed');
        expect(mockDetectHuggingFaceKeys).toHaveBeenCalledWith(content, url);
    });
});