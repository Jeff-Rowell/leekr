import { ArtifactoryDetector } from './ArtifactoryDetector';
import { detectArtifactoryKeys } from './artifactory';
import { patterns } from '../../../config/patterns';

jest.mock('./artifactory');

const mockDetectArtifactoryKeys = detectArtifactoryKeys as jest.MockedFunction<typeof detectArtifactoryKeys>;

describe('ArtifactoryDetector', () => {
    let detector: ArtifactoryDetector;

    beforeEach(() => {
        detector = new ArtifactoryDetector();
        jest.clearAllMocks();
    });

    test('has correct name and type properties', () => {
        expect(detector.name).toBe(patterns['Artifactory Access Token'].familyName);
        expect(detector.type).toBe('Artifactory');
        expect(detector.name).toBe('Artifactory');
    });

    test('calls detectArtifactoryKeys with correct parameters', async () => {
        const content = 'test content with token';
        const url = 'https://example.com/test.js';
        const expectedResult = [{
            fingerprint: 'test-fingerprint',
            secretType: 'Artifactory',
            filePath: url,
            url: url
        } as any];

        mockDetectArtifactoryKeys.mockResolvedValue(expectedResult);

        const result = await detector.detect(content, url);

        expect(mockDetectArtifactoryKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(expectedResult);
    });

    test('returns empty array when no tokens detected', async () => {
        const content = 'test content without tokens';
        const url = 'https://example.com/test.js';

        mockDetectArtifactoryKeys.mockResolvedValue([]);

        const result = await detector.detect(content, url);

        expect(mockDetectArtifactoryKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });

    test('handles multiple tokens', async () => {
        const content = 'content with multiple tokens';
        const url = 'https://example.com/test.js';
        const expectedResult = [
            { fingerprint: 'token1', secretType: 'Artifactory' },
            { fingerprint: 'token2', secretType: 'Artifactory' }
        ] as any[];

        mockDetectArtifactoryKeys.mockResolvedValue(expectedResult);

        const result = await detector.detect(content, url);

        expect(mockDetectArtifactoryKeys).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(expectedResult);
    });

    test('handles detection errors gracefully', async () => {
        const content = 'test content';
        const url = 'https://example.com/test.js';
        const error = new Error('Detection failed');

        mockDetectArtifactoryKeys.mockRejectedValue(error);

        await expect(detector.detect(content, url)).rejects.toThrow('Detection failed');
        expect(mockDetectArtifactoryKeys).toHaveBeenCalledWith(content, url);
    });
});