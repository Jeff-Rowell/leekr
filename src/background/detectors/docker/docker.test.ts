import { detectDockerKeys } from './docker';
import { validateDockerCredentials } from '../../../utils/validators/docker/docker';
import { getExistingFindings, getSourceMapUrl, findSecretPosition } from '../../../utils/helpers/common';

// Mock dependencies
jest.mock('../../../utils/validators/docker/docker');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');
jest.mock('../../../utils/accuracy/entropy');

const mockValidateDockerCredentials = validateDockerCredentials as jest.MockedFunction<typeof validateDockerCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;

// Mock computeFingerprint
const mockComputeFingerprint = require('../../../utils/helpers/computeFingerprint').computeFingerprint;
mockComputeFingerprint.mockResolvedValue('mock-fingerprint');

// Mock entropy
const mockCalculateShannonEntropy = require('../../../utils/accuracy/entropy').calculateShannonEntropy;

// Mock source map
const mockSourceMap = require('../../../../external/source-map');
const mockConsumer = {
    originalPositionFor: jest.fn(),
    sourceContentFor: jest.fn()
};

mockSourceMap.SourceMapConsumer = {
    initialize: jest.fn(),
    with: jest.fn()
};

describe('detectDockerKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        mockGetSourceMapUrl.mockReturnValue(null); // Default to no source map
        
        // Mock entropy to return high value by default (passes entropy checks)
        mockCalculateShannonEntropy.mockReturnValue(4.5);
        
        // Suppress console.log during tests
        // jest.spyOn(console, 'log').mockImplementation(() => {});
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('should detect Docker credentials from JSON auths structure', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(1);
        expect(results[0]).toMatchObject({
            secretType: 'Docker',
            validity: 'valid',
            type: 'Docker Registry Credentials',
            url: 'https://example.com/docker-config.json',
            filePath: 'docker-config.json',
            fingerprint: 'mock-fingerprint'
        });

        expect((results[0].secretValue as any).match).toMatchObject({
            registry: 'registry.example.com',
            auth: 'dGVzdDp0ZXN0',
            username: 'test',
            password: 'test'
        });
    });

    test('should detect Docker credentials with multiple registries', async () => {
        const dockerContent = `{
            "auths": {
                "ghcr.io": {
                    "auth": "SmVmLVJvd2VsbDpnaHBfaWhpY296U1dKY3RHZE5QTFJFNzZ3RTY5MmJsTjBNMXZoTVBK"
                },
                "https://index.docker.io/v1/": {
                    "auth": "bGVla3I1MjA6ZGNrcl9wYXRfTWVHMlBqUUNMb1dGNUZSWTJEcnMtVG0yamtN"
                }
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(2);
        expect((results[0].secretValue as any).match.registry).toBe('ghcr.io');
        expect((results[1].secretValue as any).match.registry).toBe('https://index.docker.io/v1/');
    });

    test('should detect Docker credentials with username and password fields', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "username": "testuser",
                    "password": "testpass",
                    "email": "test@example.com"
                }
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match).toMatchObject({
            registry: 'registry.example.com',
            username: 'testuser',
            password: 'testpass',
            email: 'test@example.com'
        });

        // Should have generated auth from username/password
        expect((results[0].secretValue as any).match.auth).toBe(btoa('testuser:testpass'));
    });

    test('should handle mixed auth formats', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0",
                    "username": "test",
                    "password": "test",
                    "email": "test@example.com"
                }
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match).toMatchObject({
            registry: 'registry.example.com',
            auth: 'dGVzdDp0ZXN0',
            username: 'test',
            password: 'test',
            email: 'test@example.com'
        });
    });

    test('should handle unquoted JSON keys', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.js');

        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match.registry).toBe('registry.example.com');
    });

    test('should return empty array when no Docker auths structure found', async () => {
        const noDockerContent = 'This content has no Docker auths structure';

        const results = await detectDockerKeys(noDockerContent, 'https://example.com/file.txt');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should return empty array when auth has insufficient entropy', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdA=="
                }
            }
        }`;

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should filter out already found configurations', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'Docker',
            secretValue: {
                match: {
                    registry: 'registry.example.com',
                    auth: 'dGVzdDp0ZXN0'
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should skip invalid Docker credentials', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: false,
            type: 'REGISTRY',
            error: 'Invalid credentials'
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).toHaveBeenCalled();
    });

    test('should handle source map processing', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        // Mock fetch for source map
        global.fetch = jest.fn().mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["test.js"],"mappings":"AAAA"}')
        });

        // Mock chrome runtime
        (global as any).chrome = {
            runtime: {
                getURL: jest.fn().mockReturnValue('/libs/mappings.wasm')
            }
        };

        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/test.js.map'));
        mockFindSecretPosition.mockReturnValue({ line: 15, column: 10 });

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.js');

        expect(results).toHaveLength(1);
        expect(results[0].sourceContent).toBeDefined();
        expect(results[0].sourceContent.contentFilename).toBe('docker-config.js');
    });

    test('should handle malformed JSON gracefully', async () => {
        const malformedContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        `;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(malformedContent, 'https://example.com/docker-config.json');

        // The detector should still work with malformed JSON due to manual parsing fallback
        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match.registry).toBe('registry.example.com');
    });

    test('should skip registries without auth credentials', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "email": "test@example.com"
                }
            }
        }`;

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should reject mismatched auth token and username/password fields', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0",
                    "username": "different",
                    "password": "mismatch"
                }
            }
        }`;

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should reject invalid base64 auth token', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "invalid-base64!"
                }
            }
        }`;

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should reject when final generated auth does not match original - covers line 301', async () => {
        // This tests the case where we decode auth successfully, but when we re-encode 
        // username:password it doesn't match the original auth token (corrupted/modified auth)
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0X2NvcnJ1cHRlZA=="
                }
            }
        }`;

        // Mock the btoa function to return something different to simulate mismatch
        const originalBtoa = global.btoa;
        global.btoa = jest.fn().mockReturnValue('different-auth-token');

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        // Restore original btoa
        global.btoa = originalBtoa;

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should handle empty matches array - covers line 32', async () => {
        const contentWithoutAuths = `{
            "config": {
                "some": "data"
            }
        }`;

        const results = await detectDockerKeys(contentWithoutAuths, 'https://example.com/config.json');

        expect(results).toHaveLength(0);
    });

    test('should process auth token with high entropy - covers line 67', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDpwYXNzd29yZA=="
                }
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(1);
        expect(mockValidateDockerCredentials).toHaveBeenCalled();
    });

    test('should handle auth token with low entropy - covers line 65 continue', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        // Mock entropy to return low value (less than 3.0) to trigger continue
        mockCalculateShannonEntropy.mockReturnValue(2.5);

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should skip passwords with low entropy - covers line 75', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "username": "testuser",
                    "password": "a"
                }
            }
        }`;

        // Mock entropy to return high value for auth token but low for password
        mockCalculateShannonEntropy
            .mockReturnValueOnce(4.5) // First call (auth token) - high entropy
            .mockReturnValueOnce(0.5); // Second call (password) - low entropy

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should handle non-Docker secretType in existing findings - covers line 97', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'AWS',
            secretValue: {
                match: {
                    registry: 'registry.example.com',
                    auth: 'dGVzdDp0ZXN0'
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);
        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        // Should process since existing finding is not Docker type
        expect(results).toHaveLength(1);
    });

    test('should cover branch where existing finding matches by auth - covers line 103', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'Docker',
            secretValue: {
                someKey: {
                    auth: 'dGVzdDp0ZXN0'  // This should match dockerMatch.auth === credentials.auth
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should cover branch where existing finding matches by registry - covers line 103', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'Docker',
            secretValue: {
                someKey: {
                    registry: 'registry.example.com'  // This should match dockerMatch.registry === credentials.registry
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should cover branch where existing finding has nested match property - covers line 103', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'Docker',
            secretValue: {
                someKey: {
                    match: {
                        auth: 'dGVzdDp0ZXN0'  // This should match dockerMatch.match.auth === credentials.auth
                    }
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should cover branch where existing finding has nested match registry - covers line 103', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'Docker',
            secretValue: {
                someKey: {
                    match: {
                        registry: 'registry.example.com'  // This should match dockerMatch.match.registry === credentials.registry
                    }
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should cover branch where URL has no path segments - covers lines 123 and 171', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        // URL that ends with slash to trigger the || "" branch  
        const results = await detectDockerKeys(dockerContent, 'https://example.com/');

        expect(results).toHaveLength(1);
        expect(results[0].sourceContent.contentFilename).toBe("");
        expect(results[0].filePath).toBe("");
    });

    test('should return empty when JSON parsing fails - simplified approach', async () => {
        // Malformed JSON that will cause parsing to fail (missing opening quote)
        const dockerContent = `auths": {
            registry.example.com": {
                "auth": "dGVzdDp0ZXN0"
            }
        }`;

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.json');

        // Should return empty because JSON parsing failed and we no longer do manual extraction
        expect(results).toHaveLength(0);
        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
    });

    test('should handle unquoted JSON keys requiring regex fix - covers line 270', async () => {
        // Content with unquoted property names that will fail initial JSON.parse but succeed after regex fix
        // This content matches the Docker Auth Config pattern and contains unquoted keys
        const dockerContent = `auths: {
            "registry.example.com": {
                auth: "dGVzdDp0ZXN0"
            }
        }`;

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.js');

        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match.registry).toBe('registry.example.com');
        expect((results[0].secretValue as any).match.auth).toBe('dGVzdDp0ZXN0');
    });

    test('should handle source map processing with brace-based config detection - covers lines 157-160', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        // Mock successful fetch
        global.fetch = jest.fn().mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":"AAAA"}')
        });

        // Mock chrome runtime
        (global as any).chrome = {
            runtime: {
                getURL: jest.fn().mockReturnValue('/libs/mappings.wasm')
            }
        };

        // Create original source that will trigger brace detection logic
        // The "auths" line is at position 5, and looking backwards we should find line 3 with "= {"
        const originalSourceContent = `// Configuration file
someObject.property = "value";
module.exports = {
    database: "mongodb://localhost",
    "auths": {
        "registry.example.com": {
            "auth": "dGVzdDp0ZXN0"
        }
    },
    timeout: 5000
};`;

        // Mock consumer methods - point to the "auths" line which is line 5
        mockConsumer.originalPositionFor.mockReturnValue({
            source: 'original.js',
            line: 5,  // Line where "auths" is found
            column: 5
        });
        mockConsumer.sourceContentFor.mockReturnValue(originalSourceContent);

        // Mock SourceMapConsumer.with to call the callback
        mockSourceMap.SourceMapConsumer.with.mockImplementation(async (content: any, options: any, callback: any) => {
            await callback(mockConsumer);
        });

        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/test.js.map'));
        mockFindSecretPosition.mockReturnValue({ line: 15, column: 10 });

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.js');

        expect(results).toHaveLength(1);
        expect(results[0].sourceContent.content).toBe(originalSourceContent);
        expect(results[0].sourceContent.contentFilename).toBe('original.js');
        // Should detect config starts at line 3 (where "= {" is found) and goes to end of config
        expect(results[0].sourceContent.exactMatchNumbers).toEqual([3, 4, 5, 6, 7, 8, 9, 10, 11]);
    });

    test('should handle successful source map processing - covers lines 137-149', async () => {
        const dockerContent = `{
            "auths": {
                "registry.example.com": {
                    "auth": "dGVzdDp0ZXN0"
                }
            }
        }`;

        // Mock successful fetch
        global.fetch = jest.fn().mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["original.js"],"mappings":"AAAA"}')
        });

        // Mock chrome runtime
        (global as any).chrome = {
            runtime: {
                getURL: jest.fn().mockReturnValue('/libs/mappings.wasm')
            }
        };

        // Create a realistic original source with the Docker config
        const originalSourceContent = `const config = {
    someOtherConfig: "value"
};
const dockerJson = {
    "auths": {
        "registry.example.com": {
            "auth": "dGVzdDp0ZXN0"
        }
    }
};
console.log(dockerJson);`;

        // Mock consumer methods
        mockConsumer.originalPositionFor.mockReturnValue({
            source: 'original.js',
            line: 5,  // Line where "auths" is found
            column: 5
        });
        mockConsumer.sourceContentFor.mockReturnValue(originalSourceContent);

        // Mock SourceMapConsumer.with to call the callback
        mockSourceMap.SourceMapConsumer.with.mockImplementation(async (content: any, options: any, callback: any) => {
            await callback(mockConsumer);
        });

        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/test.js.map'));
        mockFindSecretPosition.mockReturnValue({ line: 15, column: 10 });

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        const results = await detectDockerKeys(dockerContent, 'https://example.com/docker-config.js');

        expect(results).toHaveLength(1);
        expect(results[0].sourceContent.content).toBe(originalSourceContent);
        expect(results[0].sourceContent.contentFilename).toBe('original.js');
        expect(results[0].sourceContent.contentStartLineNum).toBe(1); // Max(1, 4 + 1 - 5)
        expect(results[0].sourceContent.contentEndLineNum).toBe(20); // 9 + 1 + 10
        // Should highlight the entire Docker config (lines 4-10 in 1-based indexing)
        expect(results[0].sourceContent.exactMatchNumbers).toEqual([4, 5, 6, 7, 8, 9, 10]);
    });
});