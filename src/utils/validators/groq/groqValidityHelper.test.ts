import { validateGroqValidity, groqValidityHelper } from './groqValidityHelper';
import { validateGroqCredentials } from './groq';
import { Finding } from '../../../types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';

jest.mock('./groq');
jest.mock('../../helpers/common');

const mockValidateGroqCredentials = validateGroqCredentials as jest.MockedFunction<typeof validateGroqCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('validateGroqValidity', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return valid result for valid credentials', async () => {
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        const result = await validateGroqValidity('gsk_' + 'a'.repeat(52));

        expect(result).toEqual({
            valid: true,
            error: null
        });
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
    });

    it('should return invalid result for invalid credentials', async () => {
        const result = await validateGroqValidity('gsk_invalid_key');

        expect(result).toEqual({
            valid: false,
            error: 'Groq API key must be 56 characters'
        });
        expect(mockValidateGroqCredentials).not.toHaveBeenCalled();
    });

    it('should return error result for network errors', async () => {
        mockValidateGroqCredentials.mockResolvedValue({
            valid: false,
            error: 'Network error'
        });

        const result = await validateGroqValidity('gsk_' + 'b'.repeat(52));

        expect(result).toEqual({
            valid: false,
            error: 'Network error'
        });
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'b'.repeat(52));
    });

    it('should return error result for validation errors', async () => {
        const result = await validateGroqValidity('');

        expect(result).toEqual({
            valid: false,
            error: 'API key is required'
        });
        expect(mockValidateGroqCredentials).not.toHaveBeenCalled();
    });

    it('should return error for invalid format', async () => {
        const result = await validateGroqValidity('gsk_' + 'a'.repeat(52) + '@'); // 57 chars with special char

        expect(result).toEqual({
            valid: false,
            error: 'Groq API key must be 56 characters'
        });
        expect(mockValidateGroqCredentials).not.toHaveBeenCalled();
    });

    it('should return error for invalid characters', async () => {
        const result = await validateGroqValidity('gsk_' + 'a'.repeat(48) + '$abc'); // 56 chars with special char

        expect(result).toEqual({
            valid: false,
            error: 'Groq API key must start with gsk_ and contain only alphanumeric characters'
        });
        expect(mockValidateGroqCredentials).not.toHaveBeenCalled();
    });
});

describe('groqValidityHelper', () => {
    const mockFinding: Finding = {
        secretType: 'Groq',
        fingerprint: 'test-fingerprint',
        validity: 'unknown',
        validatedAt: undefined,
        numOccurrences: 1,
        secretValue: {
            match: {
                apiKey: 'gsk_' + 'a'.repeat(52)
            }
        },
        occurrences: new Set()
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should update finding with valid status', async () => {
        const existingFindings = [mockFinding];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(mockFinding);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...mockFinding,
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should update finding with invalid status', async () => {
        const existingFindings = [mockFinding];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: false,
            error: null
        });

        await groqValidityHelper(mockFinding);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...mockFinding,
                validity: 'invalid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should update finding with failed_to_check status on error', async () => {
        const existingFindings = [mockFinding];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: false,
            error: 'Network error'
        });

        await groqValidityHelper(mockFinding);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...mockFinding,
                validity: 'invalid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle finding not found in existing findings', async () => {
        const existingFindings: Finding[] = [];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(mockFinding);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([]);
    });

    it('should handle finding with different secret structure', async () => {
        const findingWithDifferentStructure: Finding = {
            ...mockFinding,
            secretValue: {
                apiKey: 'gsk_' + 'b'.repeat(52)
            }
        };
        const existingFindings = [findingWithDifferentStructure];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(findingWithDifferentStructure);

        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'b'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...findingWithDifferentStructure,
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle finding with null or undefined secret value', async () => {
        const findingWithNullSecret: Finding = {
            ...mockFinding,
            secretValue: null as any
        };

        await groqValidityHelper(findingWithNullSecret);

        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockValidateGroqCredentials).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    it('should handle invalid credentials when finding exists (direct apiKey)', async () => {
        const findingWithDirectApiKey: Finding = {
            ...mockFinding,
            secretValue: {
                apiKey: 'gsk_' + 'a'.repeat(52) // Direct apiKey, not nested in match
            }
        };
        const existingFindings = [findingWithDirectApiKey];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid credentials'
        });

        await groqValidityHelper(findingWithDirectApiKey);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...findingWithDirectApiKey,
                validity: 'invalid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle valid credentials when finding validity is not invalid (direct apiKey)', async () => {
        const findingWithValidValidity: Finding = {
            ...mockFinding,
            validity: 'valid', // Not 'invalid'
            secretValue: {
                apiKey: 'gsk_' + 'a'.repeat(52) // Direct apiKey, not nested in match
            }
        };
        const existingFindings = [findingWithValidValidity];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(findingWithValidValidity);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...findingWithValidValidity,
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle occurrence with match structure', async () => {
        const findingWithMatchStructure: Finding = {
            ...mockFinding,
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'gsk_' + 'b'.repeat(52)
                    }
                }
            }
        };
        const existingFindings = [findingWithMatchStructure];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(findingWithMatchStructure);

        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'b'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...findingWithMatchStructure,
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should skip invalid occurrences and continue processing', async () => {
        const findingWithMixedOccurrences: Finding = {
            ...mockFinding,
            secretValue: {
                invalidOccurrence1: 'string_value', // Not an object
                invalidOccurrence2: null, // Null value
                invalidOccurrence3: {}, // Object without apiKey or match
                validOccurrence: {
                    apiKey: 'gsk_' + 'c'.repeat(52)
                }
            }
        };
        const existingFindings = [findingWithMixedOccurrences];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(findingWithMixedOccurrences);

        // Should only be called once for the valid occurrence
        expect(mockValidateGroqCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'c'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...findingWithMixedOccurrences,
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle invalid credentials in loop structure', async () => {
        const findingWithLoopStructure: Finding = {
            ...mockFinding,
            secretValue: {
                occurrence1: {
                    apiKey: 'gsk_' + 'd'.repeat(52)
                }
            }
        };
        const existingFindings = [findingWithLoopStructure];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid credentials'
        });

        await groqValidityHelper(findingWithLoopStructure);

        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'd'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...findingWithLoopStructure,
                validity: 'invalid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle finding with invalid validity in loop structure', async () => {
        const findingWithInvalidValidity: Finding = {
            ...mockFinding,
            validity: 'invalid',
            secretValue: {
                occurrence1: {
                    apiKey: 'gsk_' + 'e'.repeat(52)
                }
            }
        };
        const existingFindings = [findingWithInvalidValidity];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(findingWithInvalidValidity);

        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'e'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...findingWithInvalidValidity,
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    it('should handle invalid credentials when finding not found in existing findings (direct apiKey)', async () => {
        const findingWithDirectApiKey: Finding = {
            ...mockFinding,
            secretValue: {
                apiKey: 'gsk_' + 'a'.repeat(52) // Direct apiKey, not nested in match
            }
        };
        const existingFindings: Finding[] = []; // Empty array - finding not found
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid credentials'
        });

        await groqValidityHelper(findingWithDirectApiKey);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([]); // Should store empty array
    });

    it('should handle valid credentials when finding not found and validity is not invalid (direct apiKey)', async () => {
        const findingWithValidValidity: Finding = {
            ...mockFinding,
            validity: 'valid', // Not 'invalid'
            secretValue: {
                apiKey: 'gsk_' + 'a'.repeat(52) // Direct apiKey, not nested in match
            }
        };
        const existingFindings: Finding[] = []; // Empty array - finding not found
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(findingWithValidValidity);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'a'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([]); // Should store empty array
    });

    it('should handle invalid credentials when finding not found in loop structure', async () => {
        const findingWithLoopStructure: Finding = {
            ...mockFinding,
            secretValue: {
                occurrence1: {
                    apiKey: 'gsk_' + 'd'.repeat(52)
                }
            }
        };
        const existingFindings: Finding[] = []; // Empty array - finding not found
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid credentials'
        });

        await groqValidityHelper(findingWithLoopStructure);

        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'd'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([]); // Should store empty array
    });

    it('should handle finding with invalid validity when not found in loop structure', async () => {
        const findingWithInvalidValidity: Finding = {
            ...mockFinding,
            validity: 'invalid',
            secretValue: {
                occurrence1: {
                    apiKey: 'gsk_' + 'e'.repeat(52)
                }
            }
        };
        const existingFindings: Finding[] = []; // Empty array - finding not found
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateGroqCredentials.mockResolvedValue({
            valid: true,
            error: null
        });

        await groqValidityHelper(findingWithInvalidValidity);

        expect(mockValidateGroqCredentials).toHaveBeenCalledWith('gsk_' + 'e'.repeat(52));
        expect(mockStoreFindings).toHaveBeenCalledWith([]); // Should store empty array
    });
});