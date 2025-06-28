import { ApolloDetector } from './ApolloDetector';
import { detectApolloKeys } from './apollo';

jest.mock('./apollo');

const mockDetectApolloKeys = detectApolloKeys as jest.MockedFunction<typeof detectApolloKeys>;

describe('ApolloDetector', () => {
    let detector: ApolloDetector;

    beforeEach(() => {
        detector = new ApolloDetector();
        jest.clearAllMocks();
    });

    test('should have correct type and name', () => {
        expect(detector.type).toBe('Apollo');
        expect(detector.name).toBe('Apollo API Key Detector');
    });

    test('should call detectApolloKeys with correct parameters', async () => {
        const mockOccurrences = [
            {
                filePath: 'test.js',
                fingerprint: 'test-fingerprint',
                type: 'API_KEY',
                secretType: 'Apollo',
                secretValue: { match: { api_key: 'abcdefghij1234567890AB' } },
                sourceContent: {
                    content: 'test content',
                    contentFilename: 'test.js',
                    contentStartLineNum: 1,
                    contentEndLineNum: 5,
                    exactMatchNumbers: [3]
                },
                url: 'https://example.com/test.js'
            }
        ];

        mockDetectApolloKeys.mockResolvedValueOnce(mockOccurrences);

        const result = await detector.detect('test content', 'https://example.com/test.js');

        expect(mockDetectApolloKeys).toHaveBeenCalledWith('test content', 'https://example.com/test.js');
        expect(result).toEqual(mockOccurrences);
    });

    test('should return empty array when no Apollo keys found', async () => {
        mockDetectApolloKeys.mockResolvedValueOnce([]);

        const result = await detector.detect('no secrets here', 'https://example.com/test.js');

        expect(mockDetectApolloKeys).toHaveBeenCalledWith('no secrets here', 'https://example.com/test.js');
        expect(result).toEqual([]);
    });
});