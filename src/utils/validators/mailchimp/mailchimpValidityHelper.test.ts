import { validateMailchimpValidity, mailchimpValidityHelper } from './mailchimpValidityHelper';
import { validateMailchimpCredentials } from './mailchimp';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

// Mock dependencies
jest.mock('./mailchimp');
jest.mock('../../helpers/common');

const mockValidateMailchimpCredentials = validateMailchimpCredentials as jest.MockedFunction<typeof validateMailchimpCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('validateMailchimpValidity', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return error for empty API key', async () => {
        const result = await validateMailchimpValidity('');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('API key is required');
        expect(mockValidateMailchimpCredentials).not.toHaveBeenCalled();
    });

    it('should return error for whitespace only API key', async () => {
        const result = await validateMailchimpValidity('   ');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('API key is required');
        expect(mockValidateMailchimpCredentials).not.toHaveBeenCalled();
    });

    it('should return error for invalid API key format', async () => {
        const result = await validateMailchimpValidity('invalid-key-format');
        
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid Mailchimp API key format');
        expect(mockValidateMailchimpCredentials).not.toHaveBeenCalled();
    });

    it('should validate valid API key format', async () => {
        const mockValidationResult = { valid: true, error: null };
        mockValidateMailchimpCredentials.mockResolvedValue(mockValidationResult);

        const result = await validateMailchimpValidity('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result).toEqual(mockValidationResult);
        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
    });

    it('should handle validation failure', async () => {
        const mockValidationResult = { valid: false, error: 'Invalid API key' };
        mockValidateMailchimpCredentials.mockResolvedValue(mockValidationResult);

        const result = await validateMailchimpValidity('abcd1234567890abcd1234567890abcd-us12');
        
        expect(result).toEqual(mockValidationResult);
        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
    });
});

describe('mailchimpValidityHelper', () => {
    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        secretType: 'Mailchimp',
        secretValue: {},
        numOccurrences: 1,
        occurrences: new Set(),
        validity: 'unknown',
validatedAt: undefined
    };

    const mockExistingFindings: Finding[] = [
        { ...mockFinding }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);
        mockStoreFindings.mockResolvedValue(undefined);
    });

    it('should return early for invalid secretValue', async () => {
        const invalidFinding = { ...mockFinding, secretValue: null as any };
        
        await mailchimpValidityHelper(invalidFinding);
        
        expect(mockValidateMailchimpCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
    });

    it('should return early for non-object secretValue', async () => {
        const invalidFinding = { ...mockFinding, secretValue: 'not-an-object' as any };
        
        await mailchimpValidityHelper(invalidFinding);
        
        expect(mockValidateMailchimpCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
    });

    it('should handle direct apiKey in secretValue', async () => {
        const findingWithApiKey = {
            ...mockFinding,
            secretValue: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });

        await mailchimpValidityHelper(findingWithApiKey);

        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle invalid API key in direct secretValue', async () => {
        const findingWithApiKey = {
            ...mockFinding,
            secretValue: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: false, error: 'Invalid API key' });

        await mailchimpValidityHelper(findingWithApiKey);

        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'invalid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle previously invalid finding becoming valid', async () => {
        const findingWithApiKey = {
            ...mockFinding,
            validity: 'invalid' as const,
            secretValue: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });

        await mailchimpValidityHelper(findingWithApiKey);

        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle match object in secretValue', async () => {
        const findingWithMatch = {
            ...mockFinding,
            secretValue: {
                occurrence1: {
                    match: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
                }
            }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });

        await mailchimpValidityHelper(findingWithMatch);

        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle nested apiKey in secretValue', async () => {
        const findingWithNestedApiKey = {
            ...mockFinding,
            secretValue: {
                occurrence1: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
            }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });

        await mailchimpValidityHelper(findingWithNestedApiKey);

        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle invalid nested occurrence', async () => {
        const findingWithNestedApiKey = {
            ...mockFinding,
            secretValue: {
                occurrence1: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
            }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: false, error: 'Invalid API key' });

        await mailchimpValidityHelper(findingWithNestedApiKey);

        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'invalid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle previously invalid nested finding becoming valid', async () => {
        const findingWithNestedApiKey = {
            ...mockFinding,
            validity: 'invalid' as const,
            secretValue: {
                occurrence1: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
            }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });

        await mailchimpValidityHelper(findingWithNestedApiKey);

        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should skip invalid occurrence types', async () => {
        const findingWithInvalidOccurrence = {
            ...mockFinding,
            secretValue: {
                occurrence1: 'not-an-object',
                occurrence2: null,
                occurrence3: { noApiKey: 'value' }
            }
        };

        await mailchimpValidityHelper(findingWithInvalidOccurrence);

        expect(mockValidateMailchimpCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
    });

    it('should handle finding not found in existing findings', async () => {
        const findingWithApiKey = {
            ...mockFinding,
            fingerprint: 'non-existent-fingerprint',
            secretValue: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });
        mockRetrieveFindings.mockResolvedValue([]); // Empty findings array

        await mailchimpValidityHelper(findingWithApiKey);

        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
        expect(mockStoreFindings).toHaveBeenCalledWith([]); // Should still call storeFindings
    });

    it('should break after first occurrence validation', async () => {
        const findingWithMultipleOccurrences = {
            ...mockFinding,
            secretValue: {
                occurrence1: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' },
                occurrence2: { apiKey: 'efgh5678901234efgh5678901234efgh-us15' }
            }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });

        await mailchimpValidityHelper(findingWithMultipleOccurrences);

        // Should only validate the first occurrence due to break statement
        expect(mockValidateMailchimpCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
    });

    it('should handle mixed occurrence types', async () => {
        const findingWithMixedOccurrences = {
            ...mockFinding,
            secretValue: {
                invalidOccurrence: 'not-an-object',
                validOccurrence: { apiKey: 'abcd1234567890abcd1234567890abcd-us12' }
            }
        };

        mockValidateMailchimpCredentials.mockResolvedValue({ valid: true, error: null });

        await mailchimpValidityHelper(findingWithMixedOccurrences);

        expect(mockValidateMailchimpCredentials).toHaveBeenCalledWith('abcd1234567890abcd1234567890abcd-us12');
        expect(mockStoreFindings).toHaveBeenCalled();
    });
});