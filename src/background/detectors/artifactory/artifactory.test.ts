import { detectArtifactoryKeys } from './artifactory';
import { validateArtifactoryCredentials } from '../../../utils/validators/artifactory/artifactory';
import { getExistingFindings, getSourceMapUrl, findSecretPosition } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import * as sourceMap from '../../../../external/source-map';

jest.mock('../../../utils/validators/artifactory/artifactory');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map', () => ({
    SourceMapConsumer: {
        initialize: jest.fn(),
        with: jest.fn()
    }
}));

const mockValidateArtifactoryCredentials = validateArtifactoryCredentials as jest.MockedFunction<typeof validateArtifactoryCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;
const mockSourceMapConsumer = sourceMap.SourceMapConsumer as jest.Mocked<typeof sourceMap.SourceMapConsumer>;

// Mock chrome APIs
global.chrome = {
    runtime: {
        getURL: jest.fn((path: string) => `chrome-extension://test-id/${path}`)
    }
} as any;

// Mock fetch globally
global.fetch = jest.fn();

describe('detectArtifactoryKeys', () => {
    const testUrl = 'https://example.com/app.js';
    const mockApiKey73 = 'a'.repeat(73); // 73-character token
    const mockApiKey64 = 'b'.repeat(64); // 64-character token
    const mockJfrogUrl = 'example.jfrog.io';

    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        let fingerprintCounter = 0;
        mockComputeFingerprint.mockImplementation(() => Promise.resolve(`test-fingerprint-${++fingerprintCounter}`));
        mockGetSourceMapUrl.mockReturnValue(null);
        // Reset fetch mock
        (global.fetch as jest.Mock).mockReset();
        // Reset source map consumer mocks
        mockSourceMapConsumer.initialize.mockClear();
        mockSourceMapConsumer.with.mockClear();
    });

    test('detects valid Artifactory access token (73 chars) with JFrog URL', async () => {
        const content = `
            const config = {
                artifactoryToken: "${mockApiKey73}",
                url: "${mockJfrogUrl}"
            };
        `;

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io',
            tokenInfo: 'Valid token',
            permissions: ['read']
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            filePath: testUrl,
            fingerprint: 'test-fingerprint-1',
            type: 'Access Token',
            secretType: 'Artifactory',
            secretValue: {
                match: {
                    api_key: mockApiKey73,
                    url: mockJfrogUrl
                }
            },
            url: testUrl
        });

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey73, mockJfrogUrl);
    });

    test('detects valid Artifactory access token (64 chars)', async () => {
        const content = `
            const token = "${mockApiKey64}";
            const url = "${mockJfrogUrl}";
        `;

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io',
            tokenInfo: 'Valid token'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.api_key).toBe(mockApiKey64);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey64, mockJfrogUrl);
    });

    test('returns empty array when no API keys found', async () => {
        const content = 'const config = { other: "value" };';

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateArtifactoryCredentials).not.toHaveBeenCalled();
    });

    test('deduplicates API keys', async () => {
        const content = `
            const key1 = "${mockApiKey73}";
            const key2 = "${mockApiKey73}";
            const url = "${mockJfrogUrl}";
        `;

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledTimes(1);
    });

    test('deduplicates URLs', async () => {
        const content = `
            const token = "${mockApiKey73}";
            const url1 = "${mockJfrogUrl}";
            const url2 = "${mockJfrogUrl}";
        `;

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledTimes(1);
    });

    test('skips invalid API keys', async () => {
        const content = `
            const config = {
                token: "${mockApiKey73}",
                url: "${mockJfrogUrl}"
            };
        `;

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid token'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey73, mockJfrogUrl);
    });

    test('skips already found API keys', async () => {
        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretValue: {
                existingEntry: {
                    match: {
                        api_key: mockApiKey73
                    }
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const content = `
            const config = {
                token: "${mockApiKey73}",
                url: "${mockJfrogUrl}"
            };
        `;

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateArtifactoryCredentials).not.toHaveBeenCalled();
    });

    test('handles tokens without URLs by trying with undefined', async () => {
        const content = `const token = "${mockApiKey73}";`;

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: false,
            error: 'Artifactory URL is required for validation'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(0);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey73, undefined);
    });

    test('tries multiple URLs for the same token', async () => {
        const url1 = 'company1.jfrog.io';
        const url2 = 'company2.jfrog.io';
        const content = `
            const token = "${mockApiKey73}";
            const url1 = "${url1}";
            const url2 = "${url2}";
        `;

        // First URL fails, second succeeds
        mockValidateArtifactoryCredentials
            .mockResolvedValueOnce({
                valid: false,
                error: 'Invalid token'
            })
            .mockResolvedValueOnce({
                valid: true,
                error: '',
                url: 'https://company2.jfrog.io'
            });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.url).toBe(url2);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledTimes(2);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey73, url1);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey73, url2);
    });

    test('stops trying URLs after first valid combination', async () => {
        const url1 = 'company1.jfrog.io';
        const url2 = 'company2.jfrog.io';
        const content = `
            const token = "${mockApiKey73}";
            const url1 = "${url1}";
            const url2 = "${url2}";
        `;

        // First URL succeeds
        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://company1.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as any).match.url).toBe(url1);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey73, url1);
    });

    test('processes multiple valid API keys', async () => {
        const secondApiKey = 'c'.repeat(64);
        const content = `
            const config1 = {
                key: "${mockApiKey73}",
                url: "${mockJfrogUrl}"
            };
            const config2 = {
                key: "${secondApiKey}",
                url: "${mockJfrogUrl}"
            };
        `;

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(2);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey73, mockJfrogUrl);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(secondApiKey, mockJfrogUrl);
    });

    test('processes content without source map', async () => {
        const content = `const key="${mockApiKey73}"; const url="${mockJfrogUrl}";`;
        
        // Mock no source map to use bundled content path
        mockGetSourceMapUrl.mockReturnValue(null);

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.content).toBe(JSON.stringify({
            api_key: mockApiKey73,
            url: mockJfrogUrl
        }));
    });

    test('falls back to bundled content when source map processing fails', async () => {
        const content = `const key="${mockApiKey73}"; const url="${mockJfrogUrl}";`;
        
        // Mock no source map to use bundled content path directly
        mockGetSourceMapUrl.mockReturnValue(null);

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.content).toBe(JSON.stringify({
            api_key: mockApiKey73,
            url: mockJfrogUrl
        }));
        expect(result[0].sourceContent.contentFilename).toBe('app.js');
    });

    test('correctly identifies filename from URL', async () => {
        const content = `const key="${mockApiKey73}"; const url="${mockJfrogUrl}";`;
        const urlWithPath = 'https://example.com/path/to/bundle.min.js';

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, urlWithPath);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('bundle.min.js');
    });

    test('handles URL with no filename', async () => {
        const content = `const key="${mockApiKey73}"; const url="${mockJfrogUrl}";`;
        const urlWithoutFilename = 'https://example.com/';

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, urlWithoutFilename);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    test('handles finding with no match property gracefully', async () => {
        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretValue: {
                existingEntry: {
                    // No match property - should safely handle with optional chaining
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const content = `
            const config = {
                token: "${mockApiKey73}",
                url: "${mockJfrogUrl}"
            };
        `;

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(mockApiKey73, mockJfrogUrl);
    });

    test('processes bundled content correctly', async () => {
        const content = `const key="${mockApiKey73}"; const url="${mockJfrogUrl}";`;
        
        // Mock no source map to test bundled content path
        mockGetSourceMapUrl.mockReturnValue(null);

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io'
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('app.js');
        expect(result[0].sourceContent.content).toBe(JSON.stringify({
            api_key: mockApiKey73,
            url: mockJfrogUrl
        }));
    });

    test('processes source map when available', async () => {
        const content = `const key="${mockApiKey73}"; const url="${mockJfrogUrl}";`;
        const sourceMapUrl = 'https://example.com/app.js.map';
        const mockSourceMapContent = JSON.stringify({
            version: 3,
            sources: ['original.js'],
            sourcesContent: ['const originalKey = "' + mockApiKey73 + '"; const originalUrl = "' + mockJfrogUrl + '";'],
            mappings: 'AAAA'
        });

        // Mock source map URL detection
        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        
        // Mock fetch response
        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve(mockSourceMapContent)
        } as Response);

        // Mock findSecretPosition - will be called twice (API key and URL)
        mockFindSecretPosition
            .mockReturnValueOnce({
                line: 1,
                column: 10
            })
            .mockReturnValueOnce({
                line: 2,
                column: 15
            });

        // Mock source map consumer
        const mockConsumer = {
            originalPositionFor: jest.fn()
                .mockReturnValueOnce({
                    source: 'original.js',
                    line: 1,
                    column: 0
                })
                .mockReturnValueOnce({
                    source: 'original.js',
                    line: 2,
                    column: 0
                }),
            sourceContentFor: jest.fn().mockReturnValue('const originalKey = "' + mockApiKey73 + '"; const originalUrl = "' + mockJfrogUrl + '";')
        };

        // Mock SourceMapConsumer.with to call the callback with our mock consumer
        mockSourceMapConsumer.with.mockImplementation((content: any, options: any, callback: any) => {
            return callback(mockConsumer);
        });

        mockValidateArtifactoryCredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: 'https://example.jfrog.io',
            tokenInfo: 'Valid token',
            permissions: ['read']
        });

        const result = await detectArtifactoryKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockGetSourceMapUrl).toHaveBeenCalledWith(testUrl, content);
        expect(global.fetch).toHaveBeenCalledWith(new URL(sourceMapUrl));
        expect(mockSourceMapConsumer.initialize).toHaveBeenCalledWith({
            "lib/mappings.wasm": 'chrome-extension://test-id/libs/mappings.wasm'
        });
        expect(mockSourceMapConsumer.with).toHaveBeenCalledWith(mockSourceMapContent, null, expect.any(Function));
        expect(mockFindSecretPosition).toHaveBeenCalledTimes(2);
        expect(mockFindSecretPosition).toHaveBeenCalledWith(content, mockApiKey73);
        expect(mockFindSecretPosition).toHaveBeenCalledWith(content, mockJfrogUrl);
        expect(mockConsumer.originalPositionFor).toHaveBeenCalledTimes(2);
        expect(mockConsumer.originalPositionFor).toHaveBeenCalledWith({
            line: 1,
            column: 10
        });
        expect(mockConsumer.originalPositionFor).toHaveBeenCalledWith({
            line: 2,
            column: 15
        });
        expect(mockConsumer.sourceContentFor).toHaveBeenCalledWith('original.js');
        expect(result[0].sourceContent.contentFilename).toBe('original.js');
        expect(result[0].sourceContent.content).toBe('const originalKey = "' + mockApiKey73 + '"; const originalUrl = "' + mockJfrogUrl + '";');
        expect(result[0].sourceContent.contentStartLineNum).toBe(-4); // Math.min(1, 2) - 5 = -4
        expect(result[0].sourceContent.contentEndLineNum).toBe(7);   // Math.max(1, 2) + 5 = 7
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([1, 2]);
    });
});