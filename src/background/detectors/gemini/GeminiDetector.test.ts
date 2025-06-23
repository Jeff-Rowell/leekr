import { GeminiDetector } from './GeminiDetector';
import { detectGeminiKeys } from './gemini';
import { Occurrence } from '../../../types/findings.types';

jest.mock('./gemini');

describe('GeminiDetector', () => {
    let detector: GeminiDetector;
    const mockDetectGeminiKeys = detectGeminiKeys as jest.MockedFunction<typeof detectGeminiKeys>;

    beforeEach(() => {
        detector = new GeminiDetector();
        jest.clearAllMocks();
    });

    test('has correct type and name properties', () => {
        expect(detector.type).toBe('gemini');
        expect(detector.name).toBe('Gemini');
    });

    test('detect method calls detectGeminiKeys with correct parameters', async () => {
        const testContent = 'test content';
        const testUrl = 'https://example.com';
        const mockResult: Occurrence[] = [];

        mockDetectGeminiKeys.mockResolvedValue(mockResult);

        const result = await detector.detect(testContent, testUrl);

        expect(mockDetectGeminiKeys).toHaveBeenCalledWith(testContent, testUrl);
        expect(result).toBe(mockResult);
    });

    test('detect method handles errors from detectGeminiKeys', async () => {
        const testContent = 'test content';
        const testUrl = 'https://example.com';
        const error = new Error('Detection failed');

        mockDetectGeminiKeys.mockRejectedValue(error);

        await expect(detector.detect(testContent, testUrl)).rejects.toThrow('Detection failed');
    });
});