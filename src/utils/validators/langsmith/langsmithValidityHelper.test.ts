import { Finding } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { langsmithValidityHelper } from './langsmithValidityHelper';
import { validateLangsmithCredentials } from './langsmith';

jest.mock('../../helpers/common');
jest.mock('./langsmith');

const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;
const mockValidateLangsmithCredentials = validateLangsmithCredentials as jest.MockedFunction<typeof validateLangsmithCredentials>;

describe('langsmithValidityHelper', () => {
    const mockFinding: Finding = {
        secretType: 'LangSmith',
        fingerprint: 'test-fingerprint',
        secretValue: {
            match1: {
                api_key: 'lsv2_pt_12345678901234567890123456789012_1234567890'
            }
        },
        numOccurrences: 1,
        validity: 'valid',
        discoveredAt: '2024-01-01T00:00:00.000Z',
        validatedAt: '2024-01-01T00:00:00.000Z',
        occurrences: new Set()
    };

    const mockExistingFindings: Finding[] = [
        { ...mockFinding }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);
        mockStoreFindings.mockResolvedValue();
    });

    it('should mark finding as invalid when validation fails', async () => {
        mockValidateLangsmithCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Unauthorized'
        });

        await langsmithValidityHelper(mockFinding);

        expect(mockValidateLangsmithCredentials).toHaveBeenCalledWith('lsv2_pt_12345678901234567890123456789012_1234567890');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockFinding,
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should mark finding as valid when validation succeeds', async () => {
        mockValidateLangsmithCredentials.mockResolvedValue({
            valid: true,
            type: 'personal',
            error: ''
        });

        await langsmithValidityHelper(mockFinding);

        expect(mockValidateLangsmithCredentials).toHaveBeenCalledWith('lsv2_pt_12345678901234567890123456789012_1234567890');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockFinding,
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should reactivate previously invalid finding when validation succeeds', async () => {
        const invalidFinding = { ...mockFinding, validity: 'invalid' as const };
        mockRetrieveFindings.mockResolvedValue([invalidFinding]);
        mockValidateLangsmithCredentials.mockResolvedValue({
            valid: true,
            type: 'personal',
            error: ''
        });

        await langsmithValidityHelper(invalidFinding);

        expect(mockValidateLangsmithCredentials).toHaveBeenCalledWith('lsv2_pt_12345678901234567890123456789012_1234567890');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...invalidFinding,
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should skip validation when no api_key is found', async () => {
        const findingWithoutApiKey: Finding = {
            ...mockFinding,
            secretValue: {
                match1: {}
            }
        };

        await langsmithValidityHelper(findingWithoutApiKey);

        expect(mockValidateLangsmithCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    it('should handle multiple secret values', async () => {
        const findingWithMultipleValues: Finding = {
            ...mockFinding,
            secretValue: {
                match1: {
                    api_key: 'lsv2_pt_12345678901234567890123456789012_1234567890'
                },
                match2: {
                    api_key: 'lsv2_sk_abcdef01234567890123456789012345_abcdef0123'
                }
            }
        };

        mockValidateLangsmithCredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Unauthorized'
        });

        await langsmithValidityHelper(findingWithMultipleValues);

        expect(mockValidateLangsmithCredentials).toHaveBeenCalledWith('lsv2_pt_12345678901234567890123456789012_1234567890');
        expect(mockValidateLangsmithCredentials).toHaveBeenCalledTimes(1);
    });

    it('should handle empty secret value object', async () => {
        const findingWithEmptySecretValue: Finding = {
            ...mockFinding,
            secretValue: {}
        };

        await langsmithValidityHelper(findingWithEmptySecretValue);

        expect(mockValidateLangsmithCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });
});