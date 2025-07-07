import { validateMailgunValidity, mailgunValidityHelper } from './mailgunValidityHelper';
import { validateMailgunCredentials } from './mailgun';
import { Finding } from '../../../types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';

jest.mock('./mailgun');
jest.mock('../../helpers/common');

const mockValidateMailgunCredentials = validateMailgunCredentials as jest.MockedFunction<typeof validateMailgunCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('validateMailgunValidity', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return valid result for valid 72-character credentials', async () => {
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await validateMailgunValidity('a'.repeat(72));

        expect(result).toEqual({
            valid: true,
            error: ''
        });
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('a'.repeat(72));
    });

    it('should return valid result for valid key token format', async () => {
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await validateMailgunValidity('key-' + 'a'.repeat(32));

        expect(result).toEqual({
            valid: true,
            error: ''
        });
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'a'.repeat(32));
    });

    it('should return valid result for valid hex token format', async () => {
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await validateMailgunValidity('a'.repeat(32) + '-' + 'b'.repeat(8) + '-' + 'c'.repeat(8));

        expect(result).toEqual({
            valid: true,
            error: ''
        });
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('a'.repeat(32) + '-' + 'b'.repeat(8) + '-' + 'c'.repeat(8));
    });

    it('should return invalid result for invalid credentials', async () => {
        const result = await validateMailgunValidity('invalid_key');

        expect(result).toEqual({
            valid: false,
            error: 'Invalid Mailgun API key format'
        });
        expect(mockValidateMailgunCredentials).not.toHaveBeenCalled();
    });

    it('should return error result for network errors', async () => {
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: false,
            error: 'Network error'
        });

        const result = await validateMailgunValidity('key-' + 'b'.repeat(32));

        expect(result).toEqual({
            valid: false,
            error: 'Network error'
        });
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'b'.repeat(32));
    });

    it('should return error result for validation errors', async () => {
        const result = await validateMailgunValidity('');

        expect(result).toEqual({
            valid: false,
            error: 'API key is required'
        });
        expect(mockValidateMailgunCredentials).not.toHaveBeenCalled();
    });

    it('should return error for whitespace-only input', async () => {
        const result = await validateMailgunValidity('   ');

        expect(result).toEqual({
            valid: false,
            error: 'API key is required'
        });
        expect(mockValidateMailgunCredentials).not.toHaveBeenCalled();
    });
});

describe('mailgunValidityHelper', () => {
    const mockFinding: Finding = {
        secretType: 'Mailgun',
        fingerprint: 'test-fingerprint',
        validity: 'unknown',
        validatedAt: undefined,
        numOccurrences: 1,
        secretValue: {
            match: {
                apiKey: 'key-' + 'a'.repeat(32)
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
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await mailgunValidityHelper(mockFinding);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'a'.repeat(32));
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
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: false,
            error: ''
        });

        await mailgunValidityHelper(mockFinding);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'a'.repeat(32));
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
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await mailgunValidityHelper(mockFinding);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'a'.repeat(32));
        expect(mockStoreFindings).toHaveBeenCalledWith([]);
    });

    it('should handle finding with different secret structure', async () => {
        const findingWithDifferentStructure: Finding = {
            ...mockFinding,
            secretValue: {
                apiKey: 'a'.repeat(72)
            }
        };
        const existingFindings = [findingWithDifferentStructure];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await mailgunValidityHelper(findingWithDifferentStructure);

        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('a'.repeat(72));
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

        await mailgunValidityHelper(findingWithNullSecret);

        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockValidateMailgunCredentials).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    it('should handle invalid credentials when finding exists (direct apiKey)', async () => {
        const findingWithDirectApiKey: Finding = {
            ...mockFinding,
            secretValue: {
                apiKey: 'key-' + 'b'.repeat(32)
            }
        };
        const existingFindings = [findingWithDirectApiKey];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid credentials'
        });

        await mailgunValidityHelper(findingWithDirectApiKey);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'b'.repeat(32));
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
            validity: 'valid',
            secretValue: {
                apiKey: 'key-' + 'c'.repeat(32)
            }
        };
        const existingFindings = [findingWithValidValidity];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await mailgunValidityHelper(findingWithValidValidity);

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'c'.repeat(32));
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
                        apiKey: 'a'.repeat(32) + '-' + 'b'.repeat(8) + '-' + 'c'.repeat(8)
                    }
                }
            }
        };
        const existingFindings = [findingWithMatchStructure];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await mailgunValidityHelper(findingWithMatchStructure);

        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('a'.repeat(32) + '-' + 'b'.repeat(8) + '-' + 'c'.repeat(8));
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
                invalidOccurrence1: 'string_value',
                invalidOccurrence2: null,
                invalidOccurrence3: {},
                validOccurrence: {
                    apiKey: 'key-' + 'd'.repeat(32)
                }
            }
        };
        const existingFindings = [findingWithMixedOccurrences];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await mailgunValidityHelper(findingWithMixedOccurrences);

        expect(mockValidateMailgunCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'd'.repeat(32));
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
                    apiKey: 'a'.repeat(72)
                }
            }
        };
        const existingFindings = [findingWithLoopStructure];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid credentials'
        });

        await mailgunValidityHelper(findingWithLoopStructure);

        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('a'.repeat(72));
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
                    apiKey: 'key-' + 'e'.repeat(32)
                }
            }
        };
        const existingFindings = [findingWithInvalidValidity];
        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateMailgunCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await mailgunValidityHelper(findingWithInvalidValidity);

        expect(mockValidateMailgunCredentials).toHaveBeenCalledWith('key-' + 'e'.repeat(32));
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                ...findingWithInvalidValidity,
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });
});