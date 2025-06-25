import { huggingfaceValidityHelper } from './huggingfaceValidityHelper';
import { validateHuggingFaceCredentials } from './huggingface';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';
import { HuggingFaceSecretValue } from '../../../types/huggingface';

jest.mock('./huggingface');
jest.mock('../../helpers/common');

const mockValidateHuggingFaceCredentials = validateHuggingFaceCredentials as jest.MockedFunction<typeof validateHuggingFaceCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('huggingfaceValidityHelper', () => {
    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        numOccurrences: 1,
        occurrences: new Set(),
        validity: 'unknown',
        secretType: 'Hugging Face',
        secretValue: {
            match: {
                api_key: 'hf_1234567890abcdefghijklmnopqrstuv12'
            }
        } as HuggingFaceSecretValue
    };

    const mockFindings: Finding[] = [
        {
            ...mockFinding,
            validity: 'unknown',
            secretValue: {
                ...mockFinding.secretValue,
                validity: 'unknown'
            }
        }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue(mockFindings);
        mockStoreFindings.mockResolvedValue();
    });

    test('updates finding to valid when validation succeeds', async () => {
        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser',
            email: 'test@example.com',
            tokenInfo: 'My API Key (write)',
            organizations: []
        });

        await huggingfaceValidityHelper(mockFinding);

        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith('hf_1234567890abcdefghijklmnopqrstuv12');
        expect(mockRetrieveFindings).toHaveBeenCalled();
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

    test('updates finding to invalid when validation fails', async () => {
        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key'
        });

        await huggingfaceValidityHelper(mockFinding);

        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith('hf_1234567890abcdefghijklmnopqrstuv12');
        expect(mockRetrieveFindings).toHaveBeenCalled();
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

    test('updates finding to failed_to_check when validation throws error', async () => {
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
        mockValidateHuggingFaceCredentials.mockRejectedValue(new Error('Network error'));
        mockRetrieveFindings.mockResolvedValue(mockFindings);

        await huggingfaceValidityHelper(mockFinding);

        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith('hf_1234567890abcdefghijklmnopqrstuv12');
        expect(mockRetrieveFindings).toHaveBeenCalledTimes(1); // Only called once in catch
        expect(mockStoreFindings).toHaveBeenCalledTimes(1); // Only called once in catch
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
        
        consoleSpy.mockRestore();
    });

    test('updates finding to failed_to_check when retrieveFindings throws error', async () => {
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });
        mockRetrieveFindings
            .mockRejectedValueOnce(new Error('Storage error'))
            .mockResolvedValueOnce(mockFindings);

        await huggingfaceValidityHelper(mockFinding);

        expect(mockValidateHuggingFaceCredentials).toHaveBeenCalledWith('hf_1234567890abcdefghijklmnopqrstuv12');
        expect(mockRetrieveFindings).toHaveBeenCalledTimes(2); // Once for try, once for catch
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
        
        consoleSpy.mockRestore();
    });

    test('only updates the matching finding by fingerprint', async () => {
        const otherFinding: Finding = {
            fingerprint: 'other-fingerprint',
            numOccurrences: 1,
            occurrences: new Set(),
            validity: 'valid',
            secretType: 'Hugging Face',
            secretValue: {
                match: {
                    api_key: 'hf_abcdefghijklmnopqrstuvwxyz123456'
                }
            } as HuggingFaceSecretValue
        };

        const multipleFindingsList = [mockFindings[0], otherFinding];
        mockRetrieveFindings.mockResolvedValue(multipleFindingsList);

        mockValidateHuggingFaceCredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            username: 'testuser'
        });

        await huggingfaceValidityHelper(mockFinding);

        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid'
            }),
            expect.objectContaining({
                fingerprint: 'other-fingerprint',
                validity: 'valid' // Unchanged
            })
        ]);
    });

    test('handles console.error in catch block', async () => {
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
        mockValidateHuggingFaceCredentials.mockRejectedValue(new Error('Test error'));

        await huggingfaceValidityHelper(mockFinding);

        expect(consoleSpy).toHaveBeenCalledWith('Error in huggingfaceValidityHelper:', expect.any(Error));
        consoleSpy.mockRestore();
    });

    test('preserves other findings when error occurs with multiple findings', async () => {
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
        const otherFinding: Finding = {
            fingerprint: 'other-fingerprint',
            numOccurrences: 1,
            occurrences: new Set(),
            validity: 'valid',
            secretType: 'Hugging Face',
            secretValue: {
                match: {
                    api_key: 'hf_otherkeyabcdefghijklmnopqrstuvwxyz'
                }
            } as HuggingFaceSecretValue
        };

        const multipleFindingsList = [mockFindings[0], otherFinding];
        mockValidateHuggingFaceCredentials.mockRejectedValue(new Error('Network error'));
        mockRetrieveFindings.mockResolvedValue(multipleFindingsList);

        await huggingfaceValidityHelper(mockFinding);

        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'failed_to_check'
            }),
            expect.objectContaining({
                fingerprint: 'other-fingerprint',
                validity: 'valid' // Unchanged
            })
        ]);
        
        consoleSpy.mockRestore();
    });
});