import { DockerDetector } from './DockerDetector';
import { detectDockerKeys } from './docker';
import { patterns } from '../../../config/patterns';

// Mock the detectDockerKeys function
jest.mock('./docker');

const mockDetectDockerKeys = detectDockerKeys as jest.MockedFunction<typeof detectDockerKeys>;

describe('DockerDetector', () => {
    let detector: DockerDetector;

    beforeEach(() => {
        detector = new DockerDetector();
        jest.clearAllMocks();
    });

    test('should have correct type', () => {
        expect(detector.type).toBe('docker');
    });

    test('should have correct name from patterns', () => {
        expect(detector.name).toBe(patterns['Docker Auth Config'].familyName);
        expect(detector.name).toBe('Docker');
    });

    test('should call detectDockerKeys with correct parameters', async () => {
        const mockOccurrences = [
            {
                secretType: 'Docker',
                fingerprint: 'test-fingerprint',
                secretValue: {
                    match: {
                        registry: 'registry.example.com',
                        auth: 'dGVzdDp0ZXN0'
                    }
                },
                filePath: 'docker-config.json',
                url: 'https://example.com/docker-config.json',
                type: 'Docker Registry Credentials',
                validity: 'valid',
                sourceContent: {
                    content: '{}',
                    contentFilename: 'docker-config.json',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                }
            }
        ];

        mockDetectDockerKeys.mockResolvedValue(mockOccurrences);

        const content = '{"auths": {"registry.example.com": {"auth": "dGVzdDp0ZXN0"}}}';
        const url = 'https://example.com/docker-config.json';

        const result = await detector.detect(content, url);

        expect(mockDetectDockerKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(mockOccurrences);
    });

    test('should return empty array when no Docker configs are found', async () => {
        mockDetectDockerKeys.mockResolvedValue([]);

        const content = 'No Docker configs here';
        const url = 'https://example.com/file.txt';

        const result = await detector.detect(content, url);

        expect(mockDetectDockerKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });

    test('should handle multiple Docker configurations', async () => {
        const mockOccurrences = [
            {
                secretType: 'Docker',
                fingerprint: 'test-fingerprint-1',
                secretValue: {
                    match: {
                        registry: 'registry1.example.com',
                        auth: 'dGVzdDE6dGVzdDE='
                    }
                },
                filePath: 'docker-config.json',
                url: 'https://example.com/docker-config.json',
                type: 'Docker Registry Credentials',
                validity: 'valid',
                sourceContent: {
                    content: '{}',
                    contentFilename: 'docker-config.json',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                }
            },
            {
                secretType: 'Docker',
                fingerprint: 'test-fingerprint-2',
                secretValue: {
                    match: {
                        registry: 'registry2.example.com',
                        auth: 'dGVzdDI6dGVzdDI='
                    }
                },
                filePath: 'docker-config.json',
                url: 'https://example.com/docker-config.json',
                type: 'Docker Registry Credentials',
                validity: 'valid',
                sourceContent: {
                    content: '{}',
                    contentFilename: 'docker-config.json',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                }
            }
        ];

        mockDetectDockerKeys.mockResolvedValue(mockOccurrences);

        const content = `{
            "auths": {
                "registry1.example.com": {"auth": "dGVzdDE6dGVzdDE="},
                "registry2.example.com": {"auth": "dGVzdDI6dGVzdDI="}
            }
        }`;
        const url = 'https://example.com/docker-config.json';

        const result = await detector.detect(content, url);

        expect(mockDetectDockerKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(mockOccurrences);
        expect(result).toHaveLength(2);
    });

    test('should handle errors from detectDockerKeys gracefully', async () => {
        mockDetectDockerKeys.mockRejectedValue(new Error('Detection failed'));

        const content = '{"auths": {"registry.example.com": {"auth": "dGVzdDp0ZXN0"}}}';
        const url = 'https://example.com/docker-config.json';

        await expect(detector.detect(content, url)).rejects.toThrow('Detection failed');

        expect(mockDetectDockerKeys).toHaveBeenCalledWith(content, url);
    });

    test('should implement SecretDetector interface correctly', () => {
        expect(detector).toHaveProperty('type');
        expect(detector).toHaveProperty('name');
        expect(detector).toHaveProperty('detect');
        expect(typeof detector.detect).toBe('function');
    });

    test('should maintain consistency with patterns configuration', () => {
        // Ensure the detector name matches the pattern family name
        expect(detector.name).toBe(patterns['Docker Auth Config'].familyName);
        
        // Ensure the type is consistent
        expect(detector.type).toBe('docker');
    });
});