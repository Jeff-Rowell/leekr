import { jotformValidityHelper } from './jotformValidityHelper';
import { validateJotFormCredentials } from './jotform';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

jest.mock('./jotform');
jest.mock('../../helpers/common');

const mockValidateJotFormCredentials = validateJotFormCredentials as jest.MockedFunction<typeof validateJotFormCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('jotformValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should validate direct apiKey format and update invalid finding', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                apiKey: 'test123456789012345678901234567890'
            },
            validity: 'unknown'
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('test123456789012345678901234567890');
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'invalid',
            validatedAt: expect.any(String)
        }]);
    });

    test('should validate direct apiKey format and update valid finding', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                apiKey: 'test123456789012345678901234567890'
            },
            validity: 'unknown'
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('test123456789012345678901234567890');
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'valid',
            validatedAt: expect.any(String)
        }]);
    });

    test('should handle previously invalid finding becoming valid', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                apiKey: 'test123456789012345678901234567890'
            },
            validity: 'invalid'
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'valid',
            validatedAt: expect.any(String)
        }]);
    });

    test('should validate nested match format', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'test123456789012345678901234567890'
                    }
                }
            },
            validity: 'unknown'
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('test123456789012345678901234567890');
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'valid',
            validatedAt: expect.any(String)
        }]);
    });

    test('should validate occurrence with direct apiKey', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    apiKey: 'test123456789012345678901234567890'
                }
            },
            validity: 'unknown'
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('test123456789012345678901234567890');
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'valid',
            validatedAt: expect.any(String)
        }]);
    });

    test('should skip non-object occurrences', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                validity: 'unknown',
                validatedAt: '2023-01-01T00:00:00Z',
                occurrence1: {
                    apiKey: 'test123456789012345678901234567890'
                }
            }
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('test123456789012345678901234567890');
        expect(mockValidateJotFormCredentials).toHaveBeenCalledTimes(1);
    });

    test('should skip occurrences without apiKey', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    someOtherField: 'value'
                },
                occurrence2: {
                    apiKey: 'test123456789012345678901234567890'
                }
            },
            validity: 'unknown'
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('test123456789012345678901234567890');
        expect(mockValidateJotFormCredentials).toHaveBeenCalledTimes(1);
    });

    test('should break after first validation for nested format', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'test123456789012345678901234567890'
                    }
                },
                occurrence2: {
                    match: {
                        apiKey: 'another12345678901234567890123456'
                    }
                }
            },
            validity: 'unknown'
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('test123456789012345678901234567890');
    });

    test('should handle finding not in existing findings', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                apiKey: 'test123456789012345678901234567890'
            },
            validity: 'unknown'
        } as Finding;

        const existingFindings: Finding[] = [];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('test123456789012345678901234567890');
        expect(mockStoreFindings).toHaveBeenCalledWith([]);
    });

    test('should handle invalid result and break for nested format', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'invalid12345678901234567890123456'
                    }
                },
                occurrence2: {
                    match: {
                        apiKey: 'another12345678901234567890123456'
                    }
                }
            },
            validity: 'unknown'
        } as Finding;

        const existingFindings = [finding];
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });
        
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('invalid12345678901234567890123456');
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'invalid',
            validatedAt: expect.any(String)
        }]);
    });
});