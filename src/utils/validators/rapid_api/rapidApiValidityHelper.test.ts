import { rapidApiValidityHelper } from './rapidApiValidityHelper';
import { validateRapidApiCredentials } from './rapid_api';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

jest.mock('./rapid_api');
jest.mock('../../helpers/common');

const mockValidateRapidApiCredentials = validateRapidApiCredentials as jest.MockedFunction<typeof validateRapidApiCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('rapidApiValidityHelper', () => {
    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        secretType: 'RapidAPI',
        numOccurrences: 1,
        validity: 'valid',
        discoveredAt: '2023-01-01T00:00:00Z',
        occurrences: new Set(),
        secretValue: {
            '0': {
                api_key: 'testApiKey1234567890123456789012345678901234567890'
            }
        }
    };

    const mockExistingFindings: Finding[] = [
        {
            fingerprint: 'test-fingerprint',
            secretType: 'RapidAPI',
            numOccurrences: 1,
            validity: 'valid',
            discoveredAt: '2023-01-01T00:00:00Z',
            occurrences: new Set(),
            secretValue: {
                '0': {
                    api_key: 'testApiKey1234567890123456789012345678901234567890'
                }
            }
        }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue([...mockExistingFindings]);
    });

    it('should mark finding as invalid when validation fails', async () => {
        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: false,
            type: 'API_KEY',
            error: 'Unauthorized'
        });

        await rapidApiValidityHelper(mockFinding);

        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith('testApiKey1234567890123456789012345678901234567890');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        await new Promise(resolve => setTimeout(resolve, 0));
        
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should mark finding as valid when previously invalid but now valid', async () => {
        const invalidFinding = {
            ...mockFinding,
            validity: 'invalid' as const
        };

        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        await rapidApiValidityHelper(invalidFinding);

        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith('testApiKey1234567890123456789012345678901234567890');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        await new Promise(resolve => setTimeout(resolve, 0));
        
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should update timestamp when finding is still valid', async () => {
        mockValidateRapidApiCredentials.mockResolvedValue({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        await rapidApiValidityHelper(mockFinding);

        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith('testApiKey1234567890123456789012345678901234567890');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        await new Promise(resolve => setTimeout(resolve, 0));
        
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should skip occurrences without api_key', async () => {
        const findingWithoutApiKey: Finding = {
            ...mockFinding,
            secretValue: {
                '0': {
                    some_other_key: 'value'
                }
            }
        };

        await rapidApiValidityHelper(findingWithoutApiKey);

        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    it('should handle multiple occurrences and stop on first invalid', async () => {
        const findingWithMultipleKeys: Finding = {
            ...mockFinding,
            secretValue: {
                '0': {
                    api_key: 'validKey12345678901234567890123456789012345678901'
                },
                '1': {
                    api_key: 'invalidKey12345678901234567890123456789012345678901'
                }
            }
        };

        mockValidateRapidApiCredentials
            .mockResolvedValueOnce({
                valid: false,
                type: 'API_KEY',
                error: 'Unauthorized'
            });

        await rapidApiValidityHelper(findingWithMultipleKeys);

        expect(mockValidateRapidApiCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith('validKey12345678901234567890123456789012345678901');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        await new Promise(resolve => setTimeout(resolve, 0));
        
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should handle multiple occurrences and stop on first valid when previously invalid', async () => {
        const invalidFinding: Finding = {
            ...mockFinding,
            validity: 'invalid' as const,
            secretValue: {
                '0': {
                    api_key: 'validKey12345678901234567890123456789012345678901'
                },
                '1': {
                    api_key: 'anotherKey1234567890123456789012345678901234567890'
                }
            }
        };

        mockValidateRapidApiCredentials
            .mockResolvedValueOnce({
                valid: true,
                type: 'API_KEY',
                error: null
            });

        await rapidApiValidityHelper(invalidFinding);

        expect(mockValidateRapidApiCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateRapidApiCredentials).toHaveBeenCalledWith('validKey12345678901234567890123456789012345678901');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        await new Promise(resolve => setTimeout(resolve, 0));
        
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should handle empty secretValue object', async () => {
        const findingWithEmptySecretValue: Finding = {
            ...mockFinding,
            secretValue: {}
        };

        await rapidApiValidityHelper(findingWithEmptySecretValue);

        expect(mockValidateRapidApiCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });
});