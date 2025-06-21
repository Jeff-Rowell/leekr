import { AnthropicOccurrence } from 'src/types/anthropic';
import { Finding, Occurrence } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateAnthropicCredentials } from './anthropic';
import { anthropicValidityHelper } from './anthropicValidityHelper';

jest.mock('./anthropic');
jest.mock('../../helpers/common');

const mockValidateAnthropicCredentials = validateAnthropicCredentials as jest.MockedFunction<typeof validateAnthropicCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('anthropicValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    const mockAnthropicOccurrenceOne: AnthropicOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        type: "ADMIN",
        secretType: "Anthropic AI",
        secretValue: {
            match: { api_key: "sk-ant-api-test123456789" }
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

    const mockAnthropicOccurrenceTwo = {
        ...mockAnthropicOccurrenceOne,
        fingerprint: "fp2"
    };

    const mockAnthropicOccurrenceThree = {
        ...mockAnthropicOccurrenceOne,
        fingerprint: "fp3"
    };

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockAnthropicOccurrenceOne]);
    const mockOccurrencesTwo: Set<Occurrence> = new Set([mockAnthropicOccurrenceOne, mockAnthropicOccurrenceTwo]);
    const mockOccurrencesThree: Set<Occurrence> = new Set([mockAnthropicOccurrenceOne, mockAnthropicOccurrenceTwo, mockAnthropicOccurrenceThree]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrencesOne.size,
            occurrences: mockOccurrencesOne,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Anthropic AI",
            secretValue: {
                match: { api_key: "sk-ant-api-test123456789" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp2",
            numOccurrences: mockOccurrencesTwo.size,
            occurrences: mockOccurrencesTwo,
            validity: "invalid",
            secretType: "Anthropic AI",
            secretValue: {
                match: { api_key: "sk-ant-api-test123456789" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "invalid"
            }
        },
        {
            fingerprint: "fp3",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "unknown",
            secretType: "Anthropic AI",
            secretValue: {
                match: { api_key: "sk-ant-api-test123456789" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "unknown"
            }
        },
        {
            fingerprint: "fp4",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "failed_to_check",
            secretType: "Anthropic AI",
            secretValue: {
                match: { api_key: "sk-ant-api-test123456789" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "failed_to_check"
            }
        },
    ];

    test('should mark finding as invalid when Anthropic credentials validation fails', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateAnthropicCredentials.mockResolvedValue({ valid: false, type: 'unknown', error: 'Invalid key' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledWith('sk-ant-api-test123456789');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should mark finding as valid when Anthropic credentials validation succeeds and finding was previously invalid', async () => {
        const mockFinding = mockFindings[1];
        const mockExistingFindings = [mockFindings[0], mockFinding, mockFindings[2]];

        mockValidateAnthropicCredentials.mockResolvedValue({ valid: true, type: 'ADMIN', error: '' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledWith('sk-ant-api-test123456789');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when Anthropic credentials are valid and finding is already valid', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateAnthropicCredentials.mockResolvedValue({ valid: true, type: 'USER', error: '' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledWith('sk-ant-api-test123456789');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when Anthropic credentials are valid and finding has unknown validity', async () => {
        const mockFinding = mockFindings[2];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFinding];

        mockValidateAnthropicCredentials.mockResolvedValue({ valid: true, type: 'ADMIN', error: '' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledWith('sk-ant-api-test123456789');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should update timestamp when Anthropic credentials are valid and finding has failed_to_check validity', async () => {
        const mockFinding = mockFindings[3];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFindings[2], mockFinding];

        mockValidateAnthropicCredentials.mockResolvedValue({ valid: true, type: 'USER', error: '' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledWith('sk-ant-api-test123456789');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            mockFindings[2],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should handle multiple Anthropic occurrences and break on first invalid', async () => {
        const mockFinding = {
            ...mockFindings[0],
            secretValue: {
                occurrence1: { api_key: "sk-ant-api-test123456789" },
                occurrence2: { api_key: "sk-ant-api-test987654321" }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateAnthropicCredentials
            .mockResolvedValueOnce({ valid: false, type: 'unknown', error: 'Invalid key' })
            .mockResolvedValueOnce({ valid: true, type: 'ADMIN', error: '' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateAnthropicCredentials).toHaveBeenCalledWith('sk-ant-api-test123456789');

        // The stored finding should have the modified validity and timestamp
        const expectedStoredFindings = [...mockExistingFindings];
        expectedStoredFindings[0] = { ...expectedStoredFindings[0], validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' };

        expect(mockStoreFindings).toHaveBeenCalledWith(expectedStoredFindings);
    });

    test('should handle multiple Anthropic occurrences when all are valid', async () => {
        const mockFinding = {
            ...mockFindings[0],
            secretValue: {
                occurrence1: { api_key: "sk-ant-api-test123456789" },
                occurrence2: { api_key: "sk-ant-api-test987654321" }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateAnthropicCredentials
            .mockResolvedValueOnce({ valid: true, type: 'ADMIN', error: '' })
            .mockResolvedValueOnce({ valid: true, type: 'USER', error: '' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledTimes(2); // Should check both occurrences when valid (no break in else clause)
        expect(mockValidateAnthropicCredentials).toHaveBeenNthCalledWith(1, 'sk-ant-api-test123456789');
        expect(mockValidateAnthropicCredentials).toHaveBeenNthCalledWith(2, 'sk-ant-api-test987654321');

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
            secretType: 'Anthropic AI',
            secretValue: {}
        };

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).not.toHaveBeenCalled();
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
            secretType: 'Anthropic AI',
            secretValue: {
                match: { api_key: undefined }
            }
        };
        const mockExistingFindings = [mockFinding];

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle finding at index 0 in existing findings array when validation fails', async () => {
        const mockFinding = mockFindings[0]; // This finding has validity: "valid"
        const mockExistingFindings = [mockFinding, mockFindings[1], mockFindings[2]]; // mockFinding at index 0

        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
        
        // Reset all mocks to ensure clean state
        mockValidateAnthropicCredentials.mockReset();
        mockRetrieveFindings.mockReset();
        mockStoreFindings.mockReset();
        
        mockValidateAnthropicCredentials.mockResolvedValue({ valid: false, type: 'unknown', error: 'Invalid key' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledWith('sk-ant-api-test123456789');
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
                occurrence1: { api_key: null }, // No api_key
                occurrence2: { api_key: "sk-ant-api-test123456789" }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateAnthropicCredentials.mockResolvedValue({ valid: true, type: 'ADMIN', error: '' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await anthropicValidityHelper(mockFinding);

        expect(mockValidateAnthropicCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateAnthropicCredentials).toHaveBeenCalledWith('sk-ant-api-test123456789');
        expect(mockStoreFindings).toHaveBeenCalled();
    });
});