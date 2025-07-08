import { MailchimpDetector } from './MailchimpDetector';
import { detectMailchimpKeys } from './mailchimp';

// Mock the detectMailchimpKeys function
jest.mock('./mailchimp');

const mockDetectMailchimpKeys = detectMailchimpKeys as jest.MockedFunction<typeof detectMailchimpKeys>;

describe('MailchimpDetector', () => {
    let detector: MailchimpDetector;

    beforeEach(() => {
        detector = new MailchimpDetector();
        jest.clearAllMocks();
    });

    it('should have correct type and name properties', () => {
        expect(detector.type).toBe('Mailchimp');
        expect(detector.name).toBe('Mailchimp');
    });

    it('should call detectMailchimpKeys with correct parameters', async () => {
        const content = 'test content with API key';
        const url = 'https://example.com/test.js';
        const mockResult = [
            {
                secretType: 'Mailchimp',
                fingerprint: 'test-fingerprint',
                secretValue: {
                    match: {
                        apiKey: 'abcd1234567890abcd1234567890abcd-us12'
                    }
                },
                filePath: 'test.js',
                url: url,
                type: 'Mailchimp API Key',
                sourceContent: {
                    content: 'abcd1234567890abcd1234567890abcd-us12',
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];

        mockDetectMailchimpKeys.mockResolvedValue(mockResult as any);

        const result = await detector.detect(content, url);

        expect(mockDetectMailchimpKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(mockResult);
    });

    it('should return empty array when no keys are detected', async () => {
        const content = 'test content without API keys';
        const url = 'https://example.com/test.js';

        mockDetectMailchimpKeys.mockResolvedValue([]);

        const result = await detector.detect(content, url);

        expect(mockDetectMailchimpKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });

    it('should handle multiple detected keys', async () => {
        const content = 'test content with multiple API keys';
        const url = 'https://example.com/test.js';
        const mockResult = [
            {
                secretType: 'Mailchimp',
                fingerprint: 'test-fingerprint-1',
                secretValue: { match: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' } },
                filePath: 'test.js',
                url: url,
                type: 'Mailchimp API Key',
                sourceContent: {
                    content: 'abcd1234567890abcd1234567890abcd-us12',
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            },
            {
                secretType: 'Mailchimp',
                fingerprint: 'test-fingerprint-2',
                secretValue: { match: { apiKey: 'efgh5678901234efgh5678901234efgh-us15' } },
                filePath: 'test.js',
                url: url,
                type: 'Mailchimp API Key',
                sourceContent: {
                    content: 'efgh5678901234efgh5678901234efgh-us15',
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];

        mockDetectMailchimpKeys.mockResolvedValue(mockResult as any);

        const result = await detector.detect(content, url);

        expect(mockDetectMailchimpKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(mockResult);
        expect(result).toHaveLength(2);
    });

    it('should handle errors from detectMailchimpKeys', async () => {
        const content = 'test content';
        const url = 'https://example.com/test.js';
        const error = new Error('Detection failed');

        mockDetectMailchimpKeys.mockRejectedValue(error);

        await expect(detector.detect(content, url)).rejects.toThrow('Detection failed');
        expect(mockDetectMailchimpKeys).toHaveBeenCalledWith(content, url);
    });

    it('should pass through different content types', async () => {
        const testCases = [
            { content: '', url: 'https://example.com/empty.js' },
            { content: 'single line content', url: 'https://example.com/single.js' },
            { content: 'multi\nline\ncontent\nwith\nbreaks', url: 'https://example.com/multi.js' },
            { content: 'content with special chars !@#$%^&*()', url: 'https://example.com/special.js' }
        ];

        mockDetectMailchimpKeys.mockResolvedValue([]);

        for (const testCase of testCases) {
            await detector.detect(testCase.content, testCase.url);
            expect(mockDetectMailchimpKeys).toHaveBeenCalledWith(testCase.content, testCase.url);
        }

        expect(mockDetectMailchimpKeys).toHaveBeenCalledTimes(testCases.length);
    });

    it('should pass through different URL formats', async () => {
        const content = 'test content';
        const testUrls = [
            'https://example.com/test.js',
            'http://localhost:3000/bundle.js',
            'https://cdn.example.com/assets/main.min.js',
            'file:///local/path/script.js',
            'chrome-extension://id/content.js'
        ];

        mockDetectMailchimpKeys.mockResolvedValue([]);

        for (const url of testUrls) {
            await detector.detect(content, url);
            expect(mockDetectMailchimpKeys).toHaveBeenCalledWith(content, url);
        }

        expect(mockDetectMailchimpKeys).toHaveBeenCalledTimes(testUrls.length);
    });

    it('should maintain async behavior', async () => {
        const content = 'test content';
        const url = 'https://example.com/test.js';

        // Simulate async behavior
        mockDetectMailchimpKeys.mockImplementation(() => 
            new Promise(resolve => setTimeout(() => resolve([]), 10))
        );

        const startTime = Date.now();
        const result = await detector.detect(content, url);
        const endTime = Date.now();

        expect(endTime - startTime).toBeGreaterThanOrEqual(10);
        expect(result).toEqual([]);
    });
});