import { geminiValidityHelper } from './geminiValidityHelper';
import { validateGeminiCredentials } from './gemini';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

jest.mock('./gemini');
jest.mock('../../helpers/common');

const mockValidateGeminiCredentials = validateGeminiCredentials as jest.MockedFunction<typeof validateGeminiCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('geminiValidityHelper', () => {
    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        numOccurrences: 1,
        occurrences: new Set(),
        validity: 'valid',
        validatedAt: '2023-01-01T00:00:00.000Z',
        secretType: 'Gemini',
        secretValue: {
            match: {
                api_key: 'account-1234567890ABCDEFGH12',
                api_secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
            }
        }
    };

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue([mockFinding]);
    });

    test('marks finding as invalid when validation fails', async () => {
        mockValidateGeminiCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid credentials'
        });

        await geminiValidityHelper(mockFinding);

        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(
            'account-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...mockFinding,
            validity: 'invalid',
            validatedAt: expect.any(String)
        }]);
    });

    test('re-activates previously invalid finding when validation succeeds', async () => {
        const invalidFinding = { ...mockFinding, validity: 'invalid' as const };
        mockRetrieveFindings.mockResolvedValue([invalidFinding]);
        
        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        await geminiValidityHelper(invalidFinding);

        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(
            'account-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...invalidFinding,
            validity: 'valid',
            validatedAt: expect.any(String)
        }]);
    });

    test('updates timestamp for valid finding that remains valid', async () => {
        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'MASTER',
            error: '',
            account: 'primary'
        });

        await geminiValidityHelper(mockFinding);

        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(
            'account-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...mockFinding,
            validatedAt: expect.any(String)
        }]);
    });

    test('skips validation when secretValue has no api_key', async () => {
        const findingWithoutKey = {
            ...mockFinding,
            secretValue: {
                match: {
                    api_secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
                }
            }
        };

        await geminiValidityHelper(findingWithoutKey as any);

        expect(mockValidateGeminiCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('skips validation when secretValue has no api_secret', async () => {
        const findingWithoutSecret = {
            ...mockFinding,
            secretValue: {
                match: {
                    api_key: 'account-1234567890ABCDEFGH12'
                }
            }
        };

        await geminiValidityHelper(findingWithoutSecret as any);

        expect(mockValidateGeminiCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('handles multiple secretValue entries and processes first valid one', async () => {
        const findingWithMultipleValues = {
            ...mockFinding,
            secretValue: {
                firstMatch: {
                    api_secret: 'INVALID_SECRET'
                },
                secondMatch: {
                    api_key: 'account-1234567890ABCDEFGH12',
                    api_secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
                }
            }
        };

        mockValidateGeminiCredentials.mockResolvedValue({
            valid: true,
            type: 'ACCOUNT',
            error: '',
            account: 'test-account'
        });

        await geminiValidityHelper(findingWithMultipleValues as any);

        expect(mockValidateGeminiCredentials).toHaveBeenCalledWith(
            'account-1234567890ABCDEFGH12',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalled();
    });

    test('handles case when finding is not found in existing findings', async () => {
        mockRetrieveFindings.mockResolvedValue([]);
        
        mockValidateGeminiCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid credentials'
        });

        await geminiValidityHelper(mockFinding);

        expect(mockValidateGeminiCredentials).toHaveBeenCalled();
        expect(mockRetrieveFindings).toHaveBeenCalled();
        // storeFindings should not be called when finding is not found
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('handles empty secretValue object', async () => {
        const findingWithEmptySecretValue = {
            ...mockFinding,
            secretValue: {}
        };

        await geminiValidityHelper(findingWithEmptySecretValue as any);

        expect(mockValidateGeminiCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });
});