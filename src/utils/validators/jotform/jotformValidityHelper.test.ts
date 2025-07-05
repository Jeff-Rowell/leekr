import { validateJotFormValidity, jotformValidityHelper } from './jotformValidityHelper';
import { validateJotFormCredentials } from './jotform';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

jest.mock('./jotform');
jest.mock('../../helpers/common');

const mockValidateJotFormCredentials = validateJotFormCredentials as jest.MockedFunction<typeof validateJotFormCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('validateJotFormValidity', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should return invalid when API key is empty', async () => {
        const result = await validateJotFormValidity('');

        expect(result).toEqual({
            valid: false,
            error: 'API key is required'
        });

        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should return invalid when API key is only whitespace', async () => {
        const result = await validateJotFormValidity('   ');

        expect(result).toEqual({
            valid: false,
            error: 'API key is required'
        });

        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should return invalid when API key is too short', async () => {
        const result = await validateJotFormValidity('tooShort');

        expect(result).toEqual({
            valid: false,
            error: 'JotForm API key must be 32 characters'
        });

        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should return invalid when API key is too long', async () => {
        const result = await validateJotFormValidity('thisApiKeyIsTooLongForJotFormValidation');

        expect(result).toEqual({
            valid: false,
            error: 'JotForm API key must be 32 characters'
        });

        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should return invalid when API key contains special characters', async () => {
        const result = await validateJotFormValidity('apiKey@#$%^&*()12345678901234567');

        expect(result).toEqual({
            valid: false,
            error: 'JotForm API key must contain only alphanumeric characters'
        });

        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should return invalid when API key contains spaces', async () => {
        const result = await validateJotFormValidity('apiKey 1234567890123456789012345');

        expect(result).toEqual({
            valid: false,
            error: 'JotForm API key must contain only alphanumeric characters'
        });

        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
    });

    test('should call validateJotFormCredentials when API key format is valid', async () => {
        const validApiKey = 'abcdefghijklmnopqrstuvwxyz123456';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await validateJotFormValidity(validApiKey);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toEqual({
            valid: true,
            error: ''
        });
    });

    test('should return invalid result from validateJotFormCredentials', async () => {
        const validApiKey = 'abcdefghijklmnopqrstuvwxyz123456';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });

        const result = await validateJotFormValidity(validApiKey);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toEqual({
            valid: false,
            error: 'Invalid API key'
        });
    });

    test('should handle numeric API key', async () => {
        const validApiKey = '12345678901234567890123456789012';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await validateJotFormValidity(validApiKey);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toEqual({
            valid: true,
            error: ''
        });
    });

    test('should handle mixed case API key', async () => {
        const validApiKey = 'AbCdEfGhIjKlMnOpQrStUvWxYz123456';
        
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const result = await validateJotFormValidity(validApiKey);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith(validApiKey);
        expect(result).toEqual({
            valid: true,
            error: ''
        });
    });
});

describe('jotformValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should handle finding with invalid credentials changing from invalid to valid', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'abcdefghijklmnopqrstuvwxyz123456'
                    }
                }
            },
            validity: 'invalid',
            numOccurrences: 1,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ])
        );
    });

    test('should handle finding with valid credentials in else branch', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'abcdefghijklmnopqrstuvwxyz123456'
                    }
                }
            },
            validity: 'valid',
            numOccurrences: 1,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ])
        );
    });

    test('should handle finding with direct apiKey format and update invalid finding', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                apiKey: 'invalidApiKey123456789012345678901'
            },
            validity: 'valid',
            numOccurrences: 1,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({
                    validity: 'invalid',
                    validatedAt: expect.any(String)
                })
            ])
        );
    });

    test('should handle finding with direct apiKey format and update valid finding', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                apiKey: 'validApiKey123456789012345678901234'
            },
            validity: 'valid',
            numOccurrences: 1,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ])
        );
    });

    test('should handle previously invalid finding becoming valid', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                apiKey: 'validApiKey123456789012345678901234'
            },
            validity: 'invalid',
            numOccurrences: 1,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ])
        );
    });

    test('should validate nested match format', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'validApiKey123456789012345678901234'
                    }
                }
            },
            validity: 'valid',
            numOccurrences: 1,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ])
        );
    });

    test('should validate occurrence with direct apiKey', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    apiKey: 'validApiKey123456789012345678901234'
                }
            },
            validity: 'valid',
            numOccurrences: 1,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ])
        );
    });

    test('should skip non-object occurrences', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: 'notAnObject',
                occurrence2: null
            },
            validity: 'valid',
            numOccurrences: 2,
            occurrences: new Set()
        };

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should skip occurrences without apiKey', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    someOtherKey: 'value'
                },
                occurrence2: {
                    match: {
                        someOtherKey: 'value'
                    }
                }
            },
            validity: 'valid',
            numOccurrences: 2,
            occurrences: new Set()
        };

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should break after first validation for nested format', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'validApiKey123456789012345678901234'
                    }
                },
                occurrence2: {
                    match: {
                        apiKey: 'anotherApiKey123456789012345678901'
                    }
                }
            },
            validity: 'valid',
            numOccurrences: 2,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateJotFormCredentials).toHaveBeenCalledWith('validApiKey123456789012345678901234');
    });

    test('should handle finding not in existing findings', async () => {
        const finding: Finding = {
            fingerprint: 'new-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                apiKey: 'validApiKey123456789012345678901234'
            },
            validity: 'valid',
            numOccurrences: 1,
            occurrences: new Set()
        };

        const existingFindings: Finding[] = [];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        await jotformValidityHelper(finding);

        expect(mockStoreFindings).toHaveBeenCalledWith(existingFindings);
    });

    test('should handle invalid result and break for nested format', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'JotForm',
            secretValue: {
                occurrence1: {
                    match: {
                        apiKey: 'invalidApiKey123456789012345678901'
                    }
                },
                occurrence2: {
                    match: {
                        apiKey: 'anotherApiKey123456789012345678901'
                    }
                }
            },
            validity: 'valid',
            numOccurrences: 2,
            occurrences: new Set()
        };

        const existingFindings = [{ ...finding }];

        mockRetrieveFindings.mockResolvedValue(existingFindings);
        mockValidateJotFormCredentials.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });

        await jotformValidityHelper(finding);

        expect(mockValidateJotFormCredentials).toHaveBeenCalledTimes(1);
        expect(mockStoreFindings).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({
                    validity: 'invalid',
                    validatedAt: expect.any(String)
                })
            ])
        );
    });
});