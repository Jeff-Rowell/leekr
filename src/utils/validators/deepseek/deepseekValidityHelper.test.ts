import { deepseekValidityHelper } from './deepseekValidityHelper';
import { validateDeepSeekApiKey } from './deepseek';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

jest.mock('./deepseek');
jest.mock('../../helpers/common');

const mockValidateDeepSeekApiKey = validateDeepSeekApiKey as jest.MockedFunction<typeof validateDeepSeekApiKey>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('deepseekValidityHelper', () => {
    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        numOccurrences: 1,
        occurrences: new Set(),
        validity: 'unknown',
        secretType: 'DeepSeek',
        secretValue: {
            match: {
                apiKey: 'sk-abcd1234567890abcd1234567890abcd'
            }
        }
    };

    const mockExistingFindings: Finding[] = [mockFinding];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);
        mockStoreFindings.mockResolvedValue();
        jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('should update finding with valid status when API key is valid', async () => {
        mockValidateDeepSeekApiKey.mockResolvedValue({
            valid: true,
            response: { is_available: true }
        });

        await deepseekValidityHelper(mockFinding);

        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledWith('sk-abcd1234567890abcd1234567890abcd');
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String),
                secretValue: expect.objectContaining({
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            })
        ]);
    });

    test('should update finding with invalid status when API key is invalid', async () => {
        mockValidateDeepSeekApiKey.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });

        await deepseekValidityHelper(mockFinding);

        expect(mockValidateDeepSeekApiKey).toHaveBeenCalledWith('sk-abcd1234567890abcd1234567890abcd');
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'invalid',
                validatedAt: expect.any(String),
                secretValue: expect.objectContaining({
                    validity: 'invalid',
                    validatedAt: expect.any(String)
                })
            })
        ]);
    });

    test('should handle validation error and set failed_to_check status', async () => {
        mockValidateDeepSeekApiKey.mockRejectedValue(new Error('Network error'));

        await deepseekValidityHelper(mockFinding);

        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'failed_to_check',
                validatedAt: expect.any(String),
                secretValue: expect.objectContaining({
                    validity: 'failed_to_check',
                    validatedAt: expect.any(String)
                })
            })
        ]);
        expect(console.error).toHaveBeenCalledWith('Error validating DeepSeek API key:', expect.any(Error));
    });

    test('should handle missing API key gracefully', async () => {
        const findingWithoutApiKey: Finding = {
            ...mockFinding,
            secretValue: {
                match: {}
            }
        };

        await deepseekValidityHelper(findingWithoutApiKey);

        expect(mockValidateDeepSeekApiKey).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
        expect(console.error).toHaveBeenCalledWith('No API key found in finding');
    });

    test('should handle missing match object gracefully', async () => {
        const findingWithoutMatch: Finding = {
            ...mockFinding,
            secretValue: {
                match: undefined as any
            }
        };

        await deepseekValidityHelper(findingWithoutMatch);

        expect(mockValidateDeepSeekApiKey).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
        expect(console.error).toHaveBeenCalledWith('No API key found in finding');
    });

    test('should handle case where finding is not found in existing findings', async () => {
        mockRetrieveFindings.mockResolvedValue([]);
        mockValidateDeepSeekApiKey.mockResolvedValue({
            valid: true,
            response: { is_available: true }
        });

        await deepseekValidityHelper(mockFinding);

        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should preserve existing finding data when updating', async () => {
        const findingWithExtraData: Finding & { extraProperty: string } = {
            ...mockFinding,
            extraProperty: 'test'
        };
        
        mockRetrieveFindings.mockResolvedValue([findingWithExtraData]);
        mockValidateDeepSeekApiKey.mockResolvedValue({
            valid: true,
            response: { is_available: true }
        });

        await deepseekValidityHelper(findingWithExtraData);

        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                extraProperty: 'test'
            })
        ]);
    });

    test('should handle storage error gracefully', async () => {
        mockValidateDeepSeekApiKey.mockResolvedValue({
            valid: true,
            response: { is_available: true }
        });
        mockStoreFindings.mockRejectedValue(new Error('Storage error'));

        try {
            await deepseekValidityHelper(mockFinding);
        } catch (error) {
            // Expected to catch error, but also check console.error was called
        }

        expect(console.error).toHaveBeenCalledWith('Error validating DeepSeek API key:', expect.any(Error));
    });

    test('should update finding from invalid to valid when validation succeeds', async () => {
        const invalidFinding: Finding = {
            ...mockFinding,
            validity: 'invalid'
        };
        
        mockRetrieveFindings.mockResolvedValue([invalidFinding]);
        mockValidateDeepSeekApiKey.mockResolvedValue({
            valid: true,
            response: { is_available: true }
        });

        await deepseekValidityHelper(invalidFinding);

        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String),
                secretValue: expect.objectContaining({
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            })
        ]);
    });
});