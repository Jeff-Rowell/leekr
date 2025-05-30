import { awsValidityHelper } from './awsValidityHelper';
import { validateAWSCredentials } from './aws';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding, Occurrence } from 'src/types/findings.types';
import { AWSOccurrence } from 'src/types/aws.types';

jest.mock('./aws');
jest.mock('../../helpers/common');

const mockValidateAWSCredentials = validateAWSCredentials as jest.MockedFunction<typeof validateAWSCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('awsValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    const mockOccurrenceOne: AWSOccurrence = {
        accountId: "123456789876",
        arn: "arn:aws:iam::123456789876:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" }
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

    const mockOccurrenceTwo = { ...mockOccurrenceOne, accountId: "876123456789", arn: "arn:aws:iam::876123456789:user/leekr" };
    const mockOccurrenceThree = { ...mockOccurrenceOne, accountId: "987654321876", arn: "arn:aws:iam::987654321876:user/leekr" };

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockOccurrenceOne]);
    const mockOccurrencesTwo: Set<Occurrence> = new Set([mockOccurrenceOne, mockOccurrenceTwo]);
    const mockOccurrencesThree: Set<Occurrence> = new Set([mockOccurrenceOne, mockOccurrenceTwo, mockOccurrenceThree]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrencesOne.size,
            occurrences: mockOccurrencesOne,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp2",
            numOccurrences: mockOccurrencesTwo.size,
            occurrences: mockOccurrencesTwo,
            validity: "invalid",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "invalid"
            }
        },
        {
            fingerprint: "fp3",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "unknown",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "unknown"
            }
        },
        {
            fingerprint: "fp4",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "failed_to_check",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "failed_to_check"
            }
        },
    ];

    test('should mark finding as invalid when AWS credentials validation fails', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateAWSCredentials.mockResolvedValue({ valid: false });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('lol', 'wut');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should mark finding as valid when AWS credentials validation succeeds and finding was previously invalid', async () => {
        const mockFinding = mockFindings[1];
        const mockExistingFindings = [mockFindings[0], mockFinding, mockFindings[2]];

        mockValidateAWSCredentials.mockResolvedValue({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('lol', 'wut');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when AWS credentials are valid and finding is already valid', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateAWSCredentials.mockResolvedValue({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('lol', 'wut');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when AWS credentials are valid and finding has unknown validity', async () => {
        const mockFinding = mockFindings[2];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFinding];

        mockValidateAWSCredentials.mockResolvedValue({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('lol', 'wut');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should handle multiple AWS occurrences and break on first invalid', async () => {
        const mockFinding = { ...mockFindings[0] };
        mockFinding.validity = 'valid';
        const mockExistingFindings = [...mockFindings];

        mockValidateAWSCredentials
            .mockResolvedValueOnce({ valid: false })
            .mockResolvedValueOnce({ valid: true });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await awsValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateAWSCredentials).toHaveBeenCalledWith('lol', 'wut');
        expect(mockStoreFindings).toHaveBeenCalledWith([
            { ...mockFinding, validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[1],
            mockFindings[2],
            mockFindings[3],
        ]);
    });

    test('should handle empty secretValue object', async () => {
        const mockFinding: Finding = {
            fingerprint: 'fp1',
            numOccurrences: 0,
            occurrences: new Set(),
            validity: 'valid',
            validatedAt: '2025-05-17T18:16:16.870Z',
            secretType: 'AWS Access & Secret Keys',
            secretValue: {}
        };

        await awsValidityHelper(mockFinding);

        expect(mockValidateAWSCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });
});