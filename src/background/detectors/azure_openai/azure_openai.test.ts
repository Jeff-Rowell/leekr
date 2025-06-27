import { detectAzureOpenAIKeys } from './azure_openai';
import { validateAzureOpenAICredentials } from '../../../utils/validators/azure_openai/azure_openai';
import { getExistingFindings } from '../../../utils/helpers/common';

// Mock dependencies
jest.mock('../../../utils/validators/azure_openai/azure_openai');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint', () => ({
    computeFingerprint: jest.fn(() => Promise.resolve('test-fingerprint'))
}));

// Mock chrome runtime
global.chrome = {
    runtime: {
        getURL: jest.fn().mockImplementation((path: string) => `chrome-extension://test/${path}`)
    }
} as any;

// Mock fetch for source maps
global.fetch = jest.fn();

const mockValidateAzureOpenAICredentials = validateAzureOpenAICredentials as jest.MockedFunction<typeof validateAzureOpenAICredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

describe('detectAzureOpenAIKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
    });

    const validApiKey = '3ztQKWPXQXGSWHrje6TkXPKhI6gFyq1kWpFtA46YzPB4t3FsEIzxJQQJ99BFACYeBjFXJ3w3AAABACOGXpos';
    const validUrl = 'test-instance.openai.azure.com';
    const testUrl = 'https://example.com/app.js';

    test('should return empty array when no API keys found', async () => {
        const content = 'const config = { database: "postgresql://localhost" };';
        
        const result = await detectAzureOpenAIKeys(content, testUrl);
        
        expect(result).toEqual([]);
        expect(mockValidateAzureOpenAICredentials).not.toHaveBeenCalled();
    });

    test('should detect valid Azure OpenAI API key and URL combination', async () => {
        const content = `
            const azureConfig = {
                apiKey: "${validApiKey}",
                endpoint: "https://${validUrl}/openai"
            };
        `;

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: `https://${validUrl}`,
            deployments: ['gpt-35-turbo'],
            region: 'test-instance'
        });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            filePath: testUrl,
            fingerprint: 'test-fingerprint',
            type: 'API Key',
            secretType: 'Azure OpenAI',
            secretValue: {
                match: {
                    api_key: validApiKey,
                    url: validUrl
                }
            },
            url: testUrl
        });

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(validApiKey, validUrl);
    });

    test('should detect API key without URL', async () => {
        const content = `const apiKey = "${validApiKey}";`;

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: undefined
        });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect((result[0] as any).secretValue.match.url).toBeUndefined();
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(validApiKey, undefined);
    });

    test('should skip invalid API keys', async () => {
        const content = `const apiKey = "${validApiKey}";`;

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toEqual([]);
    });

    test('should deduplicate API keys and URLs', async () => {
        const content = `
            const config1 = { apiKey: "${validApiKey}", endpoint: "${validUrl}" };
            const config2 = { apiKey: "${validApiKey}", endpoint: "${validUrl}" };
        `;

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: `https://${validUrl}`
        });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledTimes(1);
    });

    test('should skip already found API keys', async () => {
        const content = `const apiKey = "${validApiKey}";`;

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'Azure OpenAI',
            secretValue: {
                match: {
                    api_key: validApiKey,
                    url: validUrl
                },
                validatedAt: '2025-05-17T18:16:16.870Z',
                validity: 'valid'
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toEqual([]);
        expect(mockValidateAzureOpenAICredentials).not.toHaveBeenCalled();
    });

    test('should handle existing findings with malformed secretValue', async () => {
        const content = `const apiKey = "${validApiKey}";`;

        const existingFindings = [
            {
                fingerprint: 'malformed-fingerprint-1',
                secretType: 'Azure OpenAI',
                secretValue: {
                    // Missing match property
                    validatedAt: '2025-05-17T18:16:16.870Z',
                    validity: 'valid'
                }
            },
            {
                fingerprint: 'malformed-fingerprint-2',
                secretType: 'Azure OpenAI',
                secretValue: {
                    match: null, // null match property
                    validatedAt: '2025-05-17T18:16:16.870Z',
                    validity: 'valid'
                }
            },
            {
                fingerprint: 'different-type',
                secretType: 'OpenAI', // Different secret type
                secretValue: {
                    match: {
                        api_key: validApiKey
                    }
                }
            }
        ];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: `https://${validUrl}`
        });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        // Should still create new occurrence since malformed findings don't match
        expect(result).toHaveLength(1);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(validApiKey, undefined);
    });

    test('should try multiple URLs with same API key', async () => {
        const url1 = 'instance1.openai.azure.com';
        const url2 = 'instance2.openai.azure.com';
        const content = `
            const apiKey = "${validApiKey}";
            const endpoint1 = "${url1}";
            const endpoint2 = "${url2}";
        `;

        mockValidateAzureOpenAICredentials
            .mockResolvedValueOnce({ valid: false, error: 'Invalid for instance1' })
            .mockResolvedValueOnce({ valid: true, error: '', url: `https://${url2}` });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect((result[0] as any).secretValue.match.url).toBe(url2);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledTimes(2);
    });

    test('should handle source map processing', async () => {
        const content = `const apiKey = "${validApiKey}";`;
        const sourceMapContent = JSON.stringify({
            version: 3,
            sources: ['original.ts'],
            sourcesContent: ['const apiKey = "original-content";'],
            mappings: 'AAAA,MAAM,MAAM,GAAG'
        });

        // Mock getSourceMapUrl to return the expected URL for this test only
        const getSourceMapUrlSpy = jest.spyOn(require('../../../utils/helpers/common'), 'getSourceMapUrl')
            .mockReturnValueOnce(new URL('https://example.com/app.js.map'));
        
        // Mock findSecretPosition
        const findSecretPositionSpy = jest.spyOn(require('../../../utils/helpers/common'), 'findSecretPosition')
            .mockReturnValue({ line: 25, column: 10 });
        
        mockFetch.mockResolvedValueOnce({
            text: () => Promise.resolve(sourceMapContent)
        } as any);

        // Mock the source map module
        const sourceMapModule = require('../../../../external/source-map');
        const originalWith = sourceMapModule.SourceMapConsumer.with;
        const originalInitialize = sourceMapModule.SourceMapConsumer.initialize;
        
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();
        sourceMapModule.SourceMapConsumer.with = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn(() => ({
                    source: 'original.ts',
                    line: 1,
                    column: 15
                })),
                sourceContentFor: jest.fn().mockReturnValue('const apiKey = "original-content";'),
            });
        });

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: `https://${validUrl}`
        });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(mockFetch).toHaveBeenCalledWith(`https://example.com/app.js.map`);
        
        // Restore everything
        getSourceMapUrlSpy.mockRestore();
        findSecretPositionSpy.mockRestore();
        sourceMapModule.SourceMapConsumer.with = originalWith;
        sourceMapModule.SourceMapConsumer.initialize = originalInitialize;
    });

    test('should handle source map processing with both API key and URL positions', async () => {
        const content = `
            const apiKey = "${validApiKey}";
            const endpoint = "${validUrl}";
        `;
        const sourceMapContent = JSON.stringify({
            version: 3,
            sources: ['original.ts'],
            sourcesContent: ['const apiKey = "original-api-key"; const endpoint = "original-url";'],
            mappings: 'AAAA,MAAM,MAAM,GAAG'
        });

        // Mock getSourceMapUrl to return the expected URL for this test only
        const getSourceMapUrlSpy = jest.spyOn(require('../../../utils/helpers/common'), 'getSourceMapUrl')
            .mockReturnValueOnce(new URL('https://example.com/app.js.map'));
        
        // Mock findSecretPosition to return different positions for key and URL
        const findSecretPositionSpy = jest.spyOn(require('../../../utils/helpers/common'), 'findSecretPosition')
            .mockReturnValueOnce({ line: 25, column: 10 })  // API key position
            .mockReturnValueOnce({ line: 26, column: 15 }); // URL position
        
        mockFetch.mockResolvedValueOnce({
            text: () => Promise.resolve(sourceMapContent)
        } as any);

        // Mock the source map module
        const sourceMapModule = require('../../../../external/source-map');
        const originalWith = sourceMapModule.SourceMapConsumer.with;
        const originalInitialize = sourceMapModule.SourceMapConsumer.initialize;
        
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();
        sourceMapModule.SourceMapConsumer.with = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn()
                    .mockReturnValueOnce({  // First call for API key
                        source: 'original.ts',
                        line: 1,
                        column: 15
                    })
                    .mockReturnValueOnce({  // Second call for URL
                        source: 'original.ts',
                        line: 2,
                        column: 20
                    }),
                sourceContentFor: jest.fn().mockReturnValue('const apiKey = "original-api-key"; const endpoint = "original-url";'),
            });
        });

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: `https://${validUrl}`
        });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([1, 2]); // Both lines included
        expect(mockFetch).toHaveBeenCalledWith(`https://example.com/app.js.map`);
        
        // Restore everything
        getSourceMapUrlSpy.mockRestore();
        findSecretPositionSpy.mockRestore();
        sourceMapModule.SourceMapConsumer.with = originalWith;
        sourceMapModule.SourceMapConsumer.initialize = originalInitialize;
    });

    test('should handle multiple API keys with different validation results', async () => {
        const apiKey1 = '3ztQKWPXQXGSWHrje6TkXPKhI6gFyq1kWpFtA46YzPB4t3FsEIzxJQQJ99BFACYeBjFXJ3w3AAABACOGXpos';
        const apiKey2 = '7lepzzduQLagoFkiYZ69sxFIierDYCjoqmNTFzqASjiN0KQkGqSxJQQJ99BFACYeBjFXJ3w3AAABACOGptIp';
        const content = `
            const key1 = "${apiKey1}";
            const key2 = "${apiKey2}";
            const endpoint = "${validUrl}";
        `;

        mockValidateAzureOpenAICredentials
            .mockResolvedValueOnce({ valid: false, error: 'Invalid key1' })
            .mockResolvedValueOnce({ valid: true, error: '', url: `https://${validUrl}` });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect((result[0] as any).secretValue.match.api_key).toBe(apiKey2);
    });

    test('should handle content with only URLs and no API keys', async () => {
        const content = `const endpoint = "${validUrl}";`;
        
        const result = await detectAzureOpenAIKeys(content, testUrl);
        
        expect(result).toEqual([]);
        expect(mockValidateAzureOpenAICredentials).not.toHaveBeenCalled();
    });

    test('should handle malformed source map gracefully', async () => {
        const content = `const apiKey = "${validApiKey}";`;
        const contentWithSourceMap = content + '\n//# sourceMappingURL=app.js.map';
        
        mockFetch.mockResolvedValueOnce({
            text: jest.fn().mockResolvedValue('invalid json')
        } as any);

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: `https://${validUrl}`
        });

        const result = await detectAzureOpenAIKeys(contentWithSourceMap, testUrl);

        expect(result).toHaveLength(1);
        // Should still create occurrence even if source map fails
        expect(result[0].sourceContent.contentFilename).toBe('app.js');
    });

    test('should match Azure OpenAI URL pattern correctly', async () => {
        const testCases = [
            'myservice.openai.azure.com',
            'test-123.openai.azure.com',
            'eastus-instance.openai.azure.com'
        ];

        for (const url of testCases) {
            const content = `const config = { apiKey: "${validApiKey}", endpoint: "${url}" };`;
            
            mockValidateAzureOpenAICredentials.mockResolvedValue({
                valid: true,
                error: '',
                url: `https://${url}`
            });

            const result = await detectAzureOpenAIKeys(content, testUrl);
            
            expect(result).toHaveLength(1);
            expect((result[0] as any).secretValue.match.url).toBe(url);
            
            // Reset for next iteration
            jest.clearAllMocks();
            mockGetExistingFindings.mockResolvedValue([]);
        }
    });

    test('should match API key pattern correctly', async () => {
        const testCases = [
            '3ztQKWPXQXGSWHrje6TkXPKhI6gFyq1kWpFtA46YzPB4t3FsEIzxJQQJ99BFACYeBjFXJ3w3AAABACOGXpos', // Real Azure key format
            '7lepzzduQLagoFkiYZ69sxFIierDYCjoqmNTFzqASjiN0KQkGqSxJQQJ99BFACYeBjFXJ3w3AAABACOGptIp', // Another real format
            '9cxozuhATQLx0Op5xu4JcwI095O8nzbfb77fqJbHG5lrURQ4qcIKJQQJ99BFACYeBjFXJ3w3AAABACOGRBr2'  // Third real format
        ];

        for (const apiKey of testCases) {
            const content = `const key = "${apiKey}";`;
            
            mockValidateAzureOpenAICredentials.mockResolvedValue({
                valid: true,
                error: '',
                url: undefined
            });

            const result = await detectAzureOpenAIKeys(content, testUrl);
            
            expect(result).toHaveLength(1);
            expect((result[0] as any).secretValue.match.api_key).toBe(apiKey);
            
            // Reset for next iteration
            jest.clearAllMocks();
            mockGetExistingFindings.mockResolvedValue([]);
        }
    });

    test('should handle empty filename fallback for URLs without filename', async () => {
        const content = `const apiKey = "${validApiKey}";`;
        
        // Mock url.split('/').pop() to return undefined by providing a URL that ends with slash
        const urlWithTrailingSlash = 'https://example.com/path/';

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: undefined
        });

        const result = await detectAzureOpenAIKeys(content, urlWithTrailingSlash);

        expect(result).toHaveLength(1);
        // When URL ends with '/', split('/').pop() returns empty string, not undefined
        // But let's also test the actual fallback case
        expect(result[0].sourceContent.contentFilename).toBe('');
        expect((result[0] as any).secretValue.match.api_key).toBe(validApiKey);
    });

    test('should handle filename extraction from various URL formats', async () => {
        const content = `const apiKey = "${validApiKey}";`;

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: undefined
        });

        // Test with URL that ends with slash - should result in empty filename
        const urlWithTrailingSlash = 'https://example.com/path/';
        const result = await detectAzureOpenAIKeys(content, urlWithTrailingSlash);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe(''); // Empty string from split('/').pop()
        expect((result[0] as any).secretValue.match.api_key).toBe(validApiKey);
    });

    test('should handle filename fallback when split returns undefined', async () => {
        const content = `const apiKey = "${validApiKey}";`;

        mockValidateAzureOpenAICredentials.mockResolvedValue({
            valid: true,
            error: '',
            url: undefined
        });

        // Mock String.prototype.split to return an array with pop returning undefined
        const originalSplit = String.prototype.split;
        String.prototype.split = jest.fn().mockReturnValue({
            pop: jest.fn().mockReturnValue(undefined)
        });

        const result = await detectAzureOpenAIKeys(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe(''); // Should use || "" fallback
        expect((result[0] as any).secretValue.match.api_key).toBe(validApiKey);

        // Restore original split
        String.prototype.split = originalSplit;
    });

    test('should validate all API keys against all URLs and return all valid combinations', async () => {
        const apiKey1 = '3ztQKWPXQXGSWHrje6TkXPKhI6gFyq1kWpFtA46YzPB4t3FsEIzxJQQJ99BFACYeBjFXJ3w3AAABACOGXpos';
        const apiKey2 = '7lepzzduQLagoFkiYZ69sxFIierDYCjoqmNTFzqASjiN0KQkGqSxJQQJ99BFACYeBjFXJ3w3AAABACOGptIp';
        const url1 = 'instance1.openai.azure.com';
        const url2 = 'instance2.openai.azure.com';
        
        const content = `
            const key1 = "${apiKey1}";
            const key2 = "${apiKey2}";
            const endpoint1 = "${url1}";
            const endpoint2 = "${url2}";
        `;

        // Mock different validation results for different combinations
        mockValidateAzureOpenAICredentials
            .mockResolvedValueOnce({ valid: true, error: '', url: `https://${url1}` })  // key1 + url1: valid
            .mockResolvedValueOnce({ valid: false, error: 'Invalid' })                   // key1 + url2: invalid
            .mockResolvedValueOnce({ valid: false, error: 'Invalid' })                   // key2 + url1: invalid
            .mockResolvedValueOnce({ valid: true, error: '', url: `https://${url2}` }); // key2 + url2: valid

        const result = await detectAzureOpenAIKeys(content, testUrl);

        // Should find 2 valid combinations
        expect(result).toHaveLength(2);
        
        // First combination: key1 + url1
        expect((result[0] as any).secretValue.match.api_key).toBe(apiKey1);
        expect((result[0] as any).secretValue.match.url).toBe(url1);
        
        // Second combination: key2 + url2
        expect((result[1] as any).secretValue.match.api_key).toBe(apiKey2);
        expect((result[1] as any).secretValue.match.url).toBe(url2);
        
        // Verify all combinations were tested
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledTimes(4);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(apiKey1, url1);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(apiKey1, url2);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(apiKey2, url1);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(apiKey2, url2);
    });
});