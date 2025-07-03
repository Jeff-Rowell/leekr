import { GcpDetector } from './GcpDetector';
import { detectGcpKeys } from './gcp';

// Mock the gcp detection function
jest.mock('./gcp');

const mockDetectGcpKeys = detectGcpKeys as jest.MockedFunction<typeof detectGcpKeys>;

describe('GcpDetector', () => {
    let detector: GcpDetector;

    beforeEach(() => {
        detector = new GcpDetector();
        jest.clearAllMocks();
    });

    test('should have correct type and name', () => {
        expect(detector.type).toBe('gcp');
        expect(detector.name).toBe('Google Cloud Platform');
    });

    test('should call detectGcpKeys with correct parameters', async () => {
        const content = 'test content with service account';
        const url = 'https://example.com/test.js';
        const mockResult: any[] = [];

        mockDetectGcpKeys.mockResolvedValueOnce(mockResult);

        const result = await detector.detect(content, url);

        expect(mockDetectGcpKeys).toHaveBeenCalledWith(content, url);
        expect(result).toBe(mockResult);
    });

    test('should return results from detectGcpKeys', async () => {
        const content = 'test content';
        const url = 'https://example.com/test.js';
        const mockOccurrences = [
            {
                secretType: 'Google Cloud Platform',
                fingerprint: 'test-fingerprint',
                secretValue: {
                    match: {
                        service_account_key: 'mock-key'
                    }
                },
                filePath: 'test.js',
                url: url,
                type: 'Service Account Key',
                sourceContent: {
                    content: 'mock content',
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                }
            }
        ];

        mockDetectGcpKeys.mockResolvedValueOnce(mockOccurrences);

        const result = await detector.detect(content, url);

        expect(result).toEqual(mockOccurrences);
        expect(result).toHaveLength(1);
    });
});