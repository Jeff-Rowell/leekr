import { detectJotFormKeys } from './jotform';
import { validateJotFormCredentials } from '../../../utils/validators/jotform/jotform';
import { getExistingFindings, getSourceMapUrl, findSecretPosition } from '../../../utils/helpers/common';

jest.mock('../../../utils/validators/jotform/jotform');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');
jest.mock('../../../utils/accuracy/entropy');
jest.mock('../../../utils/accuracy/programmingPatterns');

const mockValidateJotFormCredentials = validateJotFormCredentials as jest.MockedFunction<typeof validateJotFormCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;

const mockComputeFingerprint = require('../../../utils/helpers/computeFingerprint').computeFingerprint;
mockComputeFingerprint.mockResolvedValue('mock-fingerprint');

const mockCalculateShannonEntropy = require('../../../utils/accuracy/entropy').calculateShannonEntropy;
const mockIsProgrammingPattern = require('../../../utils/accuracy/programmingPatterns').isProgrammingPattern;

const mockSourceMap = require('../../../../external/source-map');
const mockConsumer = {
    originalPositionFor: jest.fn(),
    sourceContentFor: jest.fn()
};

mockSourceMap.SourceMapConsumer = {
    initialize: jest.fn(),
    with: jest.fn()
};

describe('detectJotFormKeys', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        mockGetSourceMapUrl.mockReturnValue(null);
        mockCalculateShannonEntropy.mockReturnValue(4.5);
        mockIsProgrammingPattern.mockReturnValue(false);
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('should detect JotForm API key with valid entropy', async () => {
        const content = 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(1);
        expect(results[0]).toMatchObject({
            secretType: 'JotForm',
            validity: 'valid',
            type: 'JotForm API Key',
            url: 'https://example.com/config.js',
            filePath: 'config.js',
            fingerprint: 'mock-fingerprint'
        });

        expect((results[0].secretValue as any).match).toMatchObject({
            apiKey: 'abcdefghijklmnopqrstuvwxyz123456'
        });
    });

    test('should detect multiple JotForm API keys', async () => {
        const content = `
            const apiKey1 = "abcdefghijklmnopqrstuvwxyz123456";
            const apiKey2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        `;
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(2);
        expect((results[0].secretValue as any).match.apiKey).toBe('abcdefghijklmnopqrstuvwxyz123456');
        expect((results[1].secretValue as any).match.apiKey).toBe('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456');
    });

    test('should return empty array when no pattern matches found', async () => {
        const content = 'This content has no JotForm API keys';

        const results = await detectJotFormKeys(content, 'https://example.com/file.txt');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should skip when capture group is missing', async () => {
        const content = 'const apiKey = "";';

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should skip when match capture group is null', async () => {
        // Using a mock to force a match with null capture group
        const content = 'test content';
        
        // Mock Array.from to return a match with null capture group
        const originalArrayFrom = Array.from;
        Array.from = jest.fn().mockReturnValue([
            [null, null]
        ]);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
        
        // Restore original Array.from
        Array.from = originalArrayFrom;
    });

    test('should skip when API key is empty after trim', async () => {
        const content = 'const apiKey = "    ";';

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should skip when API key is exactly empty string', async () => {
        // Mock Array.from to return a match with empty string
        const content = 'test content';
        
        const originalArrayFrom = Array.from;
        Array.from = jest.fn().mockReturnValue([
            ['', '']
        ]);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
        
        Array.from = originalArrayFrom;
    });

    test('should skip when API key length is not exactly 32 characters', async () => {
        // Mock Array.from to return a match with 31 characters
        const content = 'test content';
        
        const originalArrayFrom = Array.from;
        Array.from = jest.fn().mockReturnValue([
            ['1234567890123456789012345678901', '1234567890123456789012345678901']
        ]);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
        
        Array.from = originalArrayFrom;
    });

    test('should skip API keys that are not 32 characters', async () => {
        const content = 'const apiKey = "tooShort";';

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });


    test('should skip API keys with insufficient entropy', async () => {
        const content = 'const apiKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";';
        
        mockCalculateShannonEntropy.mockReturnValue(2.0);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should filter out already found API keys', async () => {
        const content = 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";';

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                match: {
                    apiKey: 'abcdefghijklmnopqrstuvwxyz123456'
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should filter out already found API keys with nested match', async () => {
        const content = 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";';

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                someKey: {
                    match: {
                        apiKey: 'abcdefghijklmnopqrstuvwxyz123456'
                    }
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should not filter findings of different secret types', async () => {
        const content = 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";';

        const existingFindings = [{
            fingerprint: 'existing-fingerprint',
            secretType: 'OpenAI',
            secretValue: {
                match: {
                    apiKey: 'abcdefghijklmnopqrstuvwxyz123456'
                }
            }
        }];

        mockGetExistingFindings.mockResolvedValue(existingFindings as any);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(1);
        expect(mockValidateJotFormCredentials).toHaveBeenCalled();
    });

    test('should skip invalid API keys', async () => {
        const content = 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockValidateJotFormCredentials).toHaveBeenCalled();
    });

    test('should handle source map processing', async () => {
        const content = 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";';

        global.fetch = jest.fn().mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["test.js"],"mappings":"AAAA"}')
        });

        (global as any).chrome = {
            runtime: {
                getURL: jest.fn().mockReturnValue('/libs/mappings.wasm')
            }
        };

        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/test.js.map'));
        mockFindSecretPosition.mockReturnValue({ line: 15, column: 10 });

        mockConsumer.originalPositionFor.mockReturnValue({
            source: 'test.js',
            line: 10,
            column: 5
        });
        mockConsumer.sourceContentFor.mockReturnValue('original source content');

        mockSourceMap.SourceMapConsumer.with.mockImplementation(async (content: any, options: any, callback: any) => {
            await callback(mockConsumer);
        });

        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(1);
        expect(results[0].sourceContent).toBeDefined();
        expect(results[0].sourceContent.content).toBe('original source content');
        expect(results[0].sourceContent.contentFilename).toBe('test.js');
        expect(results[0].sourceContent.exactMatchNumbers).toEqual([10]);
    });

    test('should handle source map processing errors gracefully', async () => {
        const content = 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";';

        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/test.js.map'));
        
        global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));

        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(1);
        expect(results[0].sourceContent.content).toBe('abcdefghijklmnopqrstuvwxyz123456');
        expect(results[0].sourceContent.contentFilename).toBe('config.js');
    });

    test('should handle URL without filename', async () => {
        const content = 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/');

        expect(results).toHaveLength(1);
        expect(results[0].sourceContent.contentFilename).toBe('');
        expect(results[0].filePath).toBe('');
    });

    test('should trim whitespace from API key', async () => {
        const content = 'const apiKey = "  abcdefghijklmnopqrstuvwxyz123456  ";';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match.apiKey).toBe('abcdefghijklmnopqrstuvwxyz123456');
    });

    test('should handle numeric API keys', async () => {
        const content = 'const apiKey = "12345678901234567890123456789012";';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match.apiKey).toBe('12345678901234567890123456789012');
    });

    test('should handle mixed case API keys', async () => {
        const content = 'const apiKey = "AbCdEfGhIjKlMnOpQrStUvWxYz123456";';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match.apiKey).toBe('AbCdEfGhIjKlMnOpQrStUvWxYz123456');
    });

    test('should skip API keys that match programming patterns', async () => {
        const content = 'const apiKey = "DisableSnapshotBlockPublicAccess";';
        
        mockIsProgrammingPattern.mockReturnValue(true);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockIsProgrammingPattern).toHaveBeenCalledWith('DisableSnapshotBlockPublicAccess');
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should detect API keys that do not match programming patterns', async () => {
        const content = 'const apiKey = "sk1234567890abcdefghijklmnopqr12";';
        
        mockIsProgrammingPattern.mockReturnValue(false);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(mockIsProgrammingPattern).toHaveBeenCalledWith('sk1234567890abcdefghijklmnopqr12');
        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('sk1234567890abcdefghijklmnopqr12');
        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match.apiKey).toBe('sk1234567890abcdefghijklmnopqr12');
    });

    test('should skip programming patterns with camelCase', async () => {
        const content = 'const apiKey = "enableNetworkAddressUsageMetrics";';
        
        mockIsProgrammingPattern.mockReturnValue(true);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockIsProgrammingPattern).toHaveBeenCalledWith('enableNetworkAddressUsageMetrics');
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should skip programming patterns with PascalCase', async () => {
        const content = 'const apiKey = "GetReservedNodeExchangeOfferings";';
        
        mockIsProgrammingPattern.mockReturnValue(true);

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(0);
        expect(mockIsProgrammingPattern).toHaveBeenCalledWith('GetReservedNodeExchangeOfferings');
        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });


    test('should use pattern from config for validation instead of hardcoded regex', async () => {
        const validApiKey = 'abcdefghijklmnopqrstuvwxyz123456';
        const content = `const apiKey = "${validApiKey}";`;
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const results = await detectJotFormKeys(content, 'https://example.com/config.js');

        expect(results).toHaveLength(1);
        expect((results[0].secretValue as any).match.apiKey).toBe(validApiKey);
        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith(validApiKey);
    });

});