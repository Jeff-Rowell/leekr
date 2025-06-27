import { AzureOpenAIDetector } from './AzureOpenAIDetector';
import { detectAzureOpenAIKeys } from './azure_openai';

// Mock the detection function
jest.mock('./azure_openai');

const mockDetectAzureOpenAIKeys = detectAzureOpenAIKeys as jest.MockedFunction<typeof detectAzureOpenAIKeys>;

describe('AzureOpenAIDetector', () => {
    let detector: AzureOpenAIDetector;

    beforeEach(() => {
        detector = new AzureOpenAIDetector();
        jest.clearAllMocks();
    });

    test('should create detector instance', () => {
        expect(detector).toBeInstanceOf(AzureOpenAIDetector);
    });

    test('should call detectAzureOpenAIKeys with correct parameters', async () => {
        const testContent = 'const apiKey = "abcdef1234567890123456789012345678";';
        const testUrl = 'https://example.com/app.js';
        const expectedOccurrences = [
            {
                filePath: testUrl,
                fingerprint: 'test-fingerprint',
                type: 'API Key',
                secretType: 'Azure OpenAI',
                secretValue: {
                    match: {
                        api_key: 'abcdef1234567890123456789012345678',
                        url: 'test-instance.openai.azure.com'
                    }
                },
                url: testUrl
            }
        ];

        mockDetectAzureOpenAIKeys.mockResolvedValue(expectedOccurrences as any);

        const result = await detector.detect(testContent, testUrl);

        expect(mockDetectAzureOpenAIKeys).toHaveBeenCalledWith(testContent, testUrl);
        expect(result).toEqual(expectedOccurrences);
    });

    test('should return empty array when no Azure OpenAI keys detected', async () => {
        const testContent = 'const config = { database: "postgresql://localhost" };';
        const testUrl = 'https://example.com/app.js';

        mockDetectAzureOpenAIKeys.mockResolvedValue([]);

        const result = await detector.detect(testContent, testUrl);

        expect(mockDetectAzureOpenAIKeys).toHaveBeenCalledWith(testContent, testUrl);
        expect(result).toEqual([]);
    });

    test('should handle multiple Azure OpenAI occurrences', async () => {
        const testContent = `
            const config1 = { apiKey: "abcdef1234567890123456789012345678901234" };
            const config2 = { apiKey: "fedcba0987654321098765432109876543210987" };
        `;
        const testUrl = 'https://example.com/app.js';
        const expectedOccurrences = [
            {
                filePath: testUrl,
                fingerprint: 'test-fingerprint-1',
                type: 'API Key',
                secretType: 'Azure OpenAI',
                secretValue: {
                    match: {
                        api_key: 'abcdef1234567890123456789012345678',
                        url: 'instance1.openai.azure.com'
                    }
                },
                url: testUrl
            },
            {
                filePath: testUrl,
                fingerprint: 'test-fingerprint-2',
                type: 'API Key',
                secretType: 'Azure OpenAI',
                secretValue: {
                    match: {
                        api_key: 'fedcba0987654321098765432109876543',
                        url: 'instance2.openai.azure.com'
                    }
                },
                url: testUrl
            }
        ];

        mockDetectAzureOpenAIKeys.mockResolvedValue(expectedOccurrences as any);

        const result = await detector.detect(testContent, testUrl);

        expect(mockDetectAzureOpenAIKeys).toHaveBeenCalledWith(testContent, testUrl);
        expect(result).toEqual(expectedOccurrences);
        expect(result).toHaveLength(2);
    });

    test('should propagate errors from detectAzureOpenAIKeys', async () => {
        const testContent = 'const apiKey = "abcdef1234567890123456789012345678";';
        const testUrl = 'https://example.com/app.js';
        const error = new Error('Detection failed');

        mockDetectAzureOpenAIKeys.mockRejectedValue(error);

        await expect(detector.detect(testContent, testUrl)).rejects.toThrow('Detection failed');
    });
});