import { JotFormDetector } from './JotFormDetector';
import { detectJotFormKeys } from './jotform';

jest.mock('./jotform');

const mockDetectJotFormKeys = detectJotFormKeys as jest.MockedFunction<typeof detectJotFormKeys>;

describe('JotFormDetector', () => {
    let detector: JotFormDetector;

    beforeEach(() => {
        detector = new JotFormDetector();
        jest.clearAllMocks();
    });

    test('should have correct type and name', () => {
        expect(detector.type).toBe('jotform');
        expect(detector.name).toBe('JotForm');
    });

    test('should call detectJotFormKeys with correct parameters', async () => {
        const content = 'test content';
        const url = 'https://example.com/test.js';
        const mockResults = [{ test: 'result' }];

        mockDetectJotFormKeys.mockResolvedValue(mockResults as any);

        const results = await detector.detect(content, url);

        expect(mockDetectJotFormKeys).toHaveBeenCalledWith(content, url);
        expect(results).toBe(mockResults);
    });

    test('should handle empty results', async () => {
        const content = 'test content';
        const url = 'https://example.com/test.js';

        mockDetectJotFormKeys.mockResolvedValue([]);

        const results = await detector.detect(content, url);

        expect(mockDetectJotFormKeys).toHaveBeenCalledWith(content, url);
        expect(results).toEqual([]);
    });

    test('should handle errors from detectJotFormKeys', async () => {
        const content = 'test content';
        const url = 'https://example.com/test.js';
        const error = new Error('Detection failed');

        mockDetectJotFormKeys.mockRejectedValue(error);

        await expect(detector.detect(content, url)).rejects.toThrow('Detection failed');
        expect(mockDetectJotFormKeys).toHaveBeenCalledWith(content, url);
    });
});