import { OpenAIDetector } from './OpenAIDetector';
import { detectOpenAIKeys } from './openai';
import { Occurrence } from '../../../types/findings.types';

jest.mock('./openai');

describe('OpenAIDetector', () => {
    let detector: OpenAIDetector;
    const mockDetectOpenAIKeys = detectOpenAIKeys as jest.MockedFunction<typeof detectOpenAIKeys>;

    beforeEach(() => {
        detector = new OpenAIDetector();
        jest.clearAllMocks();
    });

    test('has correct type and name properties', () => {
        expect(detector.type).toBe('openai');
        expect(detector.name).toBe('OpenAI');
    });

    test('detect method calls detectOpenAIKeys with correct parameters', async () => {
        const testContent = 'test content';
        const testUrl = 'https://example.com';
        const mockResult: Occurrence[] = [];

        mockDetectOpenAIKeys.mockResolvedValue(mockResult);

        const result = await detector.detect(testContent, testUrl);

        expect(mockDetectOpenAIKeys).toHaveBeenCalledWith(testContent, testUrl);
        expect(result).toBe(mockResult);
    });

    test('detect method handles errors from detectOpenAIKeys', async () => {
        const testContent = 'test content';
        const testUrl = 'https://example.com';
        const error = new Error('Detection failed');

        mockDetectOpenAIKeys.mockRejectedValue(error);

        await expect(detector.detect(testContent, testUrl)).rejects.toThrow('Detection failed');
    });
});