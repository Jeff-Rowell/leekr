import { AWSOccurrence } from 'src/types/aws.types';
import { Finding, Occurrence } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../../helpers/common';
import { validateAWSCredentials } from './aws';
import { awsSessionValidityHelper } from './awsValidityHelper';

jest.mock('./aws');
jest.mock('../../../helpers/common');

const mockValidateAWSCredentials = validateAWSCredentials as jest.MockedFunction<typeof validateAWSCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('awsSessionValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    const mockSessionOccurrenceOne: AWSOccurrence = {
        accountId: "111222333444",
        arn: "arn:aws:iam::111222333444:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        resourceType: "Session Key",
        secretType: "AWS Session Keys",
        secretValue: {
            match: { session_key_id: "session123", access_key_id: "access123", secret_key_id: "secret123" }
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

    const mockSessionOccurrenceTwo = { 
        ...mockSessionOccurrenceOne, 
        accountId: "222333444555", 
        arn: "arn:aws:iam::222333444555:user/leekr",
        fingerprint: "fp2"
    };
    const mockSessionOccurrenceThree = { 
        ...mockSessionOccurrenceOne, 
        accountId: "333444555666", 
        arn: "arn:aws:iam::333444555666:user/leekr",
        fingerprint: "fp3"
    };

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockSessionOccurrenceOne]);
    const mockOccurrencesTwo: Set<Occurrence> = new Set([mockSessionOccurrenceOne, mockSessionOccurrenceTwo]);
    const mockOccurrencesThree: Set<Occurrence> = new Set([mockSessionOccurrenceOne, mockSessionOccurrenceTwo, mockSessionOccurrenceThree]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrencesOne.size,
            occurrences: mockOccurrencesOne,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Session Keys",
            secretValue: {
                match: { session_key_id: "session123", access_key_id: "access123", secret_key_id: "secret123" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp2",
            numOccurrences: mockOccurrencesTwo.size,
            occurrences: mockOccurrencesTwo,
            validity: "invalid",
            secretType: "AWS Session Keys",
            secretValue: {
                match: { session_key_id: "session123", access_key_id: "access123", secret_key_id: "secret123" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "invalid"
            }
        },
        {
            fingerprint: "fp3",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "unknown",
            secretType: "AWS Session Keys",
            secretValue: {
                match: { session_key_id: "session123", access_key_id: "access123", secret_key_id: "secret123" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "unknown"
            }
        },
        {
            fingerprint: "fp4",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "failed_to_check",
            secretType: "AWS Session Keys",
            secretValue: {
                match: { session_key_id: "session123", access_key_id: "access123", secret_key_id: "secret123" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "failed_to_check"
            }
        },
    ];

    test('should mark finding as invalid when AWS session credentials validation fails', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateAWSCredentials.mockResolvedValue({ valid: false });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('access123', 'secret123', 'session123');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should mark finding as valid when AWS session credentials validation succeeds and finding was previously invalid', async () => {
        const mockFinding = mockFindings[1];
        const mockExistingFindings = [mockFindings[0], mockFinding, mockFindings[2]];

        mockValidateAWSCredentials.mockResolvedValue({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('access123', 'secret123', 'session123');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when AWS session credentials are valid and finding is already valid', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateAWSCredentials.mockResolvedValue({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('access123', 'secret123', 'session123');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when AWS session credentials are valid and finding has unknown validity', async () => {
        const mockFinding = mockFindings[2];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFinding];

        mockValidateAWSCredentials.mockResolvedValue({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('access123', 'secret123', 'session123');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should update timestamp when AWS session credentials are valid and finding has failed_to_check validity', async () => {
        const mockFinding = mockFindings[3];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFindings[2], mockFinding];

        mockValidateAWSCredentials.mockResolvedValue({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('access123', 'secret123', 'session123');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            mockFindings[2],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should handle multiple AWS session occurrences and break on first invalid', async () => {
        const mockFinding = { 
            ...mockFindings[0],
            secretValue: {
                occurrence1: { session_key_id: "session123", access_key_id: "access123", secret_key_id: "secret123" },
                occurrence2: { session_key_id: "session456", access_key_id: "access456", secret_key_id: "secret456" }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateAWSCredentials
            .mockResolvedValueOnce({ valid: false })
            .mockResolvedValueOnce({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('access123', 'secret123', 'session123');
        
        // The stored finding should have the modified validity and timestamp
        const expectedStoredFindings = [...mockExistingFindings];
        expectedStoredFindings[0] = { ...expectedStoredFindings[0], validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' };
        
        expect(mockStoreFindings).toHaveBeenCalledWith(expectedStoredFindings);
    });

    test('should handle multiple AWS session occurrences when all are valid', async () => {
        const mockFinding = { 
            ...mockFindings[0],
            secretValue: {
                occurrence1: { session_key_id: "session123", access_key_id: "access123", secret_key_id: "secret123" },
                occurrence2: { session_key_id: "session456", access_key_id: "access456", secret_key_id: "secret456" }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateAWSCredentials
            .mockResolvedValueOnce({ valid: true })
            .mockResolvedValueOnce({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledTimes(2); // Checks all occurrences when valid (no break in else clause)
        expect(mockValidateAWSCredentials).toHaveBeenNthCalledWith(1, 'access123', 'secret123', 'session123');
        expect(mockValidateAWSCredentials).toHaveBeenNthCalledWith(2, 'access456', 'secret456', 'session456');
        
        // The stored finding should have the modified validity and timestamp (called for each occurrence)
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
            secretType: 'AWS Session Keys',
            secretValue: {}
        };

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle secretValue with undefined properties', async () => {
        const mockFinding: Finding = {
            fingerprint: 'fp1',
            numOccurrences: 1,
            occurrences: mockOccurrencesOne,
            validity: 'valid',
            validatedAt: '2025-05-17T18:16:16.870Z',
            secretType: 'AWS Session Keys',
            secretValue: {
                match: { session_key_id: undefined, access_key_id: undefined, secret_key_id: undefined }
            }
        };
        const mockExistingFindings = [mockFinding];

        mockValidateAWSCredentials.mockResolvedValue({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith(undefined, undefined, undefined);
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should handle finding at index 0 in existing findings array', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFinding, mockFindings[1], mockFindings[2]]; // mockFinding at index 0

        mockValidateAWSCredentials.mockResolvedValue({ valid: false });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsSessionValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('access123', 'secret123', 'session123');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            { ...mockFinding, validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[1],
            mockFindings[2]
        ]);
    });
});