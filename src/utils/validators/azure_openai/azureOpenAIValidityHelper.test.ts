import { AzureOpenAIOccurrence } from 'src/types/azure_openai';
import { Finding, Occurrence } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateAzureOpenAICredentials } from './azure_openai';
import { azureOpenAIValidityHelper } from './azureOpenAIValidityHelper';

jest.mock('./azure_openai');
jest.mock('../../helpers/common');

const mockValidateAzureOpenAICredentials = validateAzureOpenAICredentials as jest.MockedFunction<typeof validateAzureOpenAICredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('azureOpenAIValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    const mockAzureOpenAIOccurrenceOne: AzureOpenAIOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        type: "API_KEY",
        secretType: "Azure OpenAI",
        secretValue: {
            match: { 
                api_key: "abcdef1234567890123456789012345678",
                url: "test-instance.openai.azure.com"
            }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockAzureOpenAIOccurrenceTwo = {
        ...mockAzureOpenAIOccurrenceOne,
        fingerprint: "fp2"
    };

    const mockAzureOpenAIOccurrenceThree = {
        ...mockAzureOpenAIOccurrenceOne,
        fingerprint: "fp3"
    };

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockAzureOpenAIOccurrenceOne]);
    const mockOccurrencesTwo: Set<Occurrence> = new Set([mockAzureOpenAIOccurrenceOne, mockAzureOpenAIOccurrenceTwo]);
    const mockOccurrencesThree: Set<Occurrence> = new Set([mockAzureOpenAIOccurrenceOne, mockAzureOpenAIOccurrenceTwo, mockAzureOpenAIOccurrenceThree]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrencesOne.size,
            occurrences: mockOccurrencesOne,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Azure OpenAI",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678",
                    url: "test-instance.openai.azure.com"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp2",
            numOccurrences: mockOccurrencesTwo.size,
            occurrences: mockOccurrencesTwo,
            validity: "invalid",
            secretType: "Azure OpenAI",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678",
                    url: "test-instance.openai.azure.com"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "invalid"
            }
        },
        {
            fingerprint: "fp3",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "unknown",
            secretType: "Azure OpenAI",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678",
                    url: "test-instance.openai.azure.com"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "unknown"
            }
        },
        {
            fingerprint: "fp4",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "failed_to_check",
            secretType: "Azure OpenAI",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678",
                    url: "test-instance.openai.azure.com"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "failed_to_check"
            }
        },
    ];

    test('should mark finding as invalid when Azure OpenAI credentials validation fails', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateAzureOpenAICredentials.mockResolvedValue({ valid: false, error: 'Invalid API key' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should mark finding as valid when Azure OpenAI credentials validation succeeds and finding was previously invalid', async () => {
        const mockFinding = mockFindings[1];
        const mockExistingFindings = [mockFindings[0], mockFinding, mockFindings[2]];

        mockValidateAzureOpenAICredentials.mockResolvedValue({ 
            valid: true, 
            error: '', 
            url: 'https://test-instance.openai.azure.com',
            deployments: ['gpt-35-turbo'],
            region: 'test-instance'
        });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when Azure OpenAI credentials are valid and finding is already valid', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateAzureOpenAICredentials.mockResolvedValue({ 
            valid: true, 
            error: '', 
            url: 'https://test-instance.openai.azure.com' 
        });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when Azure OpenAI credentials are valid and finding has unknown validity', async () => {
        const mockFinding = mockFindings[2];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFinding];

        mockValidateAzureOpenAICredentials.mockResolvedValue({ 
            valid: true, 
            error: '', 
            url: 'https://test-instance.openai.azure.com' 
        });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should update timestamp when Azure OpenAI credentials are valid and finding has failed_to_check validity', async () => {
        const mockFinding = mockFindings[3];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFindings[2], mockFinding];

        mockValidateAzureOpenAICredentials.mockResolvedValue({ 
            valid: true, 
            error: '', 
            url: 'https://test-instance.openai.azure.com' 
        });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            mockFindings[2],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should handle multiple Azure OpenAI occurrences and break on first invalid', async () => {
        const mockFinding = {
            ...mockFindings[0],
            secretValue: {
                occurrence1: { 
                    api_key: "abcdef1234567890123456789012345678",
                    url: "test-instance.openai.azure.com"
                },
                occurrence2: { 
                    api_key: "zyxwvu9876543210987654321098765432",
                    url: "test2-instance.openai.azure.com"
                }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateAzureOpenAICredentials
            .mockResolvedValueOnce({ valid: false, error: 'Invalid API key' })
            .mockResolvedValueOnce({ valid: true, error: '', url: 'https://test2-instance.openai.azure.com' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );

        // The stored finding should have the modified validity and timestamp
        const expectedStoredFindings = [...mockExistingFindings];
        expectedStoredFindings[0] = { ...expectedStoredFindings[0], validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' };

        expect(mockStoreFindings).toHaveBeenCalledWith(expectedStoredFindings);
    });

    test('should handle multiple Azure OpenAI occurrences when all are valid', async () => {
        const mockFinding = {
            ...mockFindings[0],
            secretValue: {
                occurrence1: { 
                    api_key: "abcdef1234567890123456789012345678",
                    url: "test-instance.openai.azure.com"
                },
                occurrence2: { 
                    api_key: "zyxwvu9876543210987654321098765432",
                    url: "test2-instance.openai.azure.com"
                }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateAzureOpenAICredentials
            .mockResolvedValueOnce({ valid: true, error: '', url: 'https://test-instance.openai.azure.com' })
            .mockResolvedValueOnce({ valid: true, error: '', url: 'https://test2-instance.openai.azure.com' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledTimes(2); // Should check both occurrences when valid (no break in else clause)
        expect(mockValidateAzureOpenAICredentials).toHaveBeenNthCalledWith(1, 
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );
        expect(mockValidateAzureOpenAICredentials).toHaveBeenNthCalledWith(2, 
            'zyxwvu9876543210987654321098765432',
            'test2-instance.openai.azure.com'
        );

        // The stored finding should have the modified validity and timestamp
        const expectedStoredFindings = [...mockExistingFindings];
        expectedStoredFindings[0] = { ...expectedStoredFindings[0], validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' };

        expect(mockStoreFindings).toHaveBeenCalledTimes(2); // Called once for each valid occurrence
        expect(mockStoreFindings).toHaveBeenLastCalledWith(expectedStoredFindings);
    });

    test('should handle empty secretValue object', async () => {
        const mockFinding: Finding = {
            fingerprint: 'fp1',
            numOccurrences: 0,
            occurrences: new Set(),
            validity: 'valid',
            validatedAt: '2025-05-17T18:16:16.870Z',
            secretType: 'Azure OpenAI',
            secretValue: {}
        };

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle secretValue with undefined api_key properties', async () => {
        const mockFinding: Finding = {
            fingerprint: 'fp1',
            numOccurrences: 1,
            occurrences: mockOccurrencesOne,
            validity: 'valid',
            validatedAt: '2025-05-17T18:16:16.870Z',
            secretType: 'Azure OpenAI',
            secretValue: {
                match: { api_key: undefined, url: "test-instance.openai.azure.com" }
            }
        };

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle finding at index 0 in existing findings array when validation fails', async () => {
        const mockFinding = mockFindings[0]; // This finding has validity: "valid"
        const mockExistingFindings = [mockFinding, mockFindings[1], mockFindings[2]]; // mockFinding at index 0

        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
        
        // Reset all mocks to ensure clean state
        mockValidateAzureOpenAICredentials.mockReset();
        mockRetrieveFindings.mockReset();
        mockStoreFindings.mockReset();
        
        mockValidateAzureOpenAICredentials.mockResolvedValue({ valid: false, error: 'Invalid API key' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            { ...mockFinding, validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[1],
            mockFindings[2]
        ]);
    });

    test('should skip occurrences without api_key and continue processing others', async () => {
        const mockFinding = {
            ...mockFindings[0],
            secretValue: {
                occurrence1: { api_key: null, url: "test-instance.openai.azure.com" }, // No api_key
                occurrence2: { 
                    api_key: "abcdef1234567890123456789012345678",
                    url: "test-instance.openai.azure.com"
                }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateAzureOpenAICredentials.mockResolvedValue({ 
            valid: true, 
            error: '', 
            url: 'https://test-instance.openai.azure.com' 
        });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await azureOpenAIValidityHelper(mockFinding);

        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateAzureOpenAICredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678',
            'test-instance.openai.azure.com'
        );
        expect(mockStoreFindings).toHaveBeenCalled();
    });
});