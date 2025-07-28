import { LangsmithDetector } from './LangsmithDetector';
import { detectLangsmith } from './langsmith';
import { patterns } from '../../../config/patterns';

jest.mock('./langsmith');

const mockDetectLangsmith = detectLangsmith as jest.MockedFunction<typeof detectLangsmith>;

describe('LangsmithDetector', () => {
    let detector: LangsmithDetector;

    beforeEach(() => {
        detector = new LangsmithDetector();
        jest.clearAllMocks();
    });

    it('should have correct type', () => {
        expect(detector.type).toBe('langsmith');
    });

    it('should have correct name from patterns', () => {
        expect(detector.name).toBe(patterns['LangSmith API Key'].familyName);
    });

    it('should call detectLangsmith with correct parameters', async () => {
        const mockOccurrences = [
            {
                secretType: 'LangSmith',
                fingerprint: 'test-fingerprint',
                secretValue: {
                    match: {
                        api_key: 'lsv2_pt_12345678901234567890123456789012_1234567890'
                    }
                },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'Personal API Token',
                sourceContent: {
                    content: '{"api_key":"lsv2_pt_1234567890123456789012345678901234567890ab"}',
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];

        mockDetectLangsmith.mockResolvedValue(mockOccurrences);

        const content = 'const apiKey = "lsv2_pt_12345678901234567890123456789012_1234567890";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectLangsmith).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(mockOccurrences);
    });

    it('should return empty array when no matches found', async () => {
        mockDetectLangsmith.mockResolvedValue([]);

        const content = 'const apiKey = "invalid-key";';
        const url = 'https://example.com/test.js';

        const result = await detector.detect(content, url);

        expect(mockDetectLangsmith).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });
});