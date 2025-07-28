import { detectLangsmith } from './langsmith';
import { patterns } from '../../../config/patterns';
import { LangsmithOccurrence } from '../../../types/langsmith';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { validateLangsmithCredentials } from '../../../utils/validators/langsmith/langsmith';

jest.mock('../../../utils/accuracy/entropy');
jest.mock('../../../utils/accuracy/falsePositives');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../utils/validators/langsmith/langsmith');
jest.mock('../../../../external/source-map', () => ({
    SourceMapConsumer: {
        initialize: jest.fn(),
        with: jest.fn()
    }
}));

const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;
const mockIsKnownFalsePositive = isKnownFalsePositive as jest.MockedFunction<typeof isKnownFalsePositive>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;
const mockValidateLangsmithCredentials = validateLangsmithCredentials as jest.MockedFunction<typeof validateLangsmithCredentials>;

global.fetch = jest.fn();

describe('detectLangsmith', () => {
    const validPersonalToken = 'lsv2_pt_12345678901234567890123456789012_1234567890';
    const validServiceKey = 'lsv2_sk_abcdef01234567890123456789012345_abcdef0123';
    const testUrl = 'https://example.com/test.js';

    beforeEach(() => {
        jest.clearAllMocks();
        mockCalculateShannonEntropy.mockReturnValue(5.0);
        mockIsKnownFalsePositive.mockReturnValue([false, '']);
        mockGetExistingFindings.mockResolvedValue([]);
        mockGetSourceMapUrl.mockReturnValue(null);
        mockComputeFingerprint.mockResolvedValue('test-fingerprint');
        mockValidateLangsmithCredentials.mockResolvedValue({
            valid: true,
            type: 'personal',
            error: ''
        });
    });

    it('should detect valid personal token', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;

        const result = await detectLangsmith(content, testUrl);

        expect(result).toHaveLength(1);
        const langsmithResult = result[0] as LangsmithOccurrence;
        expect(langsmithResult.secretValue.match.api_key).toBe(validPersonalToken);
        expect(langsmithResult.type).toBe('Personal API Token');
        expect(langsmithResult.validity).toBe('valid');
    });

    it('should detect valid service key', async () => {
        const content = `const apiKey = "${validServiceKey}";`;
        mockValidateLangsmithCredentials.mockResolvedValue({
            valid: true,
            type: 'service',
            error: ''
        });

        const result = await detectLangsmith(content, testUrl);

        expect(result).toHaveLength(1);
        const langsmithResult = result[0] as LangsmithOccurrence;
        expect(langsmithResult.secretValue.match.api_key).toBe(validServiceKey);
        expect(langsmithResult.type).toBe('Service Key');
        expect(langsmithResult.validity).toBe('valid');
    });

    it('should return empty array when no matches found', async () => {
        const content = 'const apiKey = "invalid-key";';

        const result = await detectLangsmith(content, testUrl);

        expect(result).toEqual([]);
    });

    it('should filter out low entropy matches', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        mockCalculateShannonEntropy.mockReturnValue(-0.1);

        const result = await detectLangsmith(content, testUrl);

        expect(result).toEqual([]);
    });

    it('should filter out known false positives', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        mockIsKnownFalsePositive.mockReturnValue([true, 'test pattern']);

        const result = await detectLangsmith(content, testUrl);

        expect(result).toEqual([]);
    });

    it('should filter out already found secrets', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        mockGetExistingFindings.mockResolvedValue([
            {
                secretType: 'LangSmith',
                fingerprint: 'existing-fingerprint',
                secretValue: {
                    match: {
                        api_key: validPersonalToken
                    }
                },
                numOccurrences: 1,
                validity: 'valid',
                discoveredAt: '2024-01-01T00:00:00.000Z',
                validatedAt: '2024-01-01T00:00:00.000Z',
                occurrences: new Set()
            }
        ]);

        const result = await detectLangsmith(content, testUrl);

        expect(result).toEqual([]);
    });

    it('should not return invalid secrets', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        mockValidateLangsmithCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Unauthorized'
        });

        const result = await detectLangsmith(content, testUrl);

        expect(result).toEqual([]);
    });

    it('should handle source map processing', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        const sourceMapUrl = new URL('https://example.com/test.js.map');
        const sourceMapContent = '{"version":3,"sources":["test.ts"],"mappings":"AAAA"}';
        
        mockGetSourceMapUrl.mockReturnValue(sourceMapUrl);
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 15 });
        
        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve(sourceMapContent)
        });

        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: 'test.ts',
                line: 1,
                column: 15
            }),
            sourceContentFor: jest.fn().mockReturnValue('const apiKey = "' + validPersonalToken + '";')
        };

        const sourceMap = require('../../../../external/source-map');
        sourceMap.SourceMapConsumer.initialize.mockImplementation(() => {});
        sourceMap.SourceMapConsumer.with.mockImplementation((content: any, options: any, callback: any) => {
            callback(mockConsumer);
        });

        Object.defineProperty(global, 'chrome', {
            value: {
                runtime: {
                    getURL: jest.fn().mockReturnValue('chrome-extension://test/libs/mappings.wasm')
                }
            },
            writable: true
        });

        const result = await detectLangsmith(content, testUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('test.ts');
        expect(result[0].sourceContent.contentStartLineNum).toBe(-4);
        expect(result[0].sourceContent.contentEndLineNum).toBe(6);
        expect(result[0].sourceContent.exactMatchNumbers).toEqual([1]);
    });

    it('should handle multiple matches', async () => {
        const content = `
            const token1 = "${validPersonalToken}";
            const token2 = "${validServiceKey}";
        `;

        const result = await detectLangsmith(content, testUrl);

        expect(result).toHaveLength(2);
        const langsmithResult1 = result[0] as LangsmithOccurrence;
        const langsmithResult2 = result[1] as LangsmithOccurrence;
        expect(langsmithResult1.secretValue.match.api_key).toBe(validPersonalToken);
        expect(langsmithResult2.secretValue.match.api_key).toBe(validServiceKey);
    });

    it('should set correct filePath from URL', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        const urlWithPath = 'https://example.com/path/to/test.js';

        const result = await detectLangsmith(content, urlWithPath);

        expect(result[0].filePath).toBe('test.js');
    });

    it('should handle URL without filename', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        const urlWithoutFilename = 'https://example.com/';

        const result = await detectLangsmith(content, urlWithoutFilename);

        expect(result[0].filePath).toBe('');
    });

    it('should use correct entropy threshold from patterns', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        const mockEntropy = patterns['LangSmith API Key'].entropy + 0.1;
        mockCalculateShannonEntropy.mockReturnValue(mockEntropy);

        const result = await detectLangsmith(content, testUrl);

        expect(calculateShannonEntropy).toHaveBeenCalledWith(validPersonalToken);
        expect(result).toHaveLength(1);
    });


    it('should compute fingerprint correctly', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;

        await detectLangsmith(content, testUrl);

        expect(mockComputeFingerprint).toHaveBeenCalledWith(
            { match: { api_key: validPersonalToken } },
            'SHA-512'
        );
    });

    it('should use correct secret type from patterns', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;

        const result = await detectLangsmith(content, testUrl);

        expect(result[0].secretType).toBe(patterns['LangSmith API Key'].familyName);
    });

    it('should handle regex match failures gracefully', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        
        jest.spyOn(String.prototype, 'match')
            .mockImplementationOnce(() => [validPersonalToken])
            .mockImplementationOnce(() => null)
            .mockImplementationOnce(() => null);

        const result = await detectLangsmith(content, testUrl);

        expect(result).toEqual([]);
    });

    it('should handle null regex match in filteredMatches processing', async () => {
        const content = `const apiKey = "${validPersonalToken}";`;
        
        // Mock String.prototype.match to return null specifically for the filteredMatches processing
        const originalMatch = String.prototype.match;
        jest.spyOn(String.prototype, 'match')
            .mockImplementationOnce(() => [validPersonalToken]) // Initial pattern match
            .mockImplementationOnce(() => [validPersonalToken, validPersonalToken]) // validMatches filter
            .mockImplementationOnce(() => null); // filteredMatches processing - line 41

        const result = await detectLangsmith(content, testUrl);

        expect(result).toEqual([]);
        
        // Restore original implementation
        String.prototype.match = originalMatch;
    });
});