import { ArtifactoryOccurrence } from 'src/types/artifactory';
import { Finding, Occurrence } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateArtifactoryCredentials } from './artifactory';
import { artifactoryValidityHelper } from './artifactoryValidityHelper';

jest.mock('./artifactory');
jest.mock('../../helpers/common');

const mockValidateArtifactoryCredentials = validateArtifactoryCredentials as jest.MockedFunction<typeof validateArtifactoryCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('artifactoryValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    const mockArtifactoryOccurrenceOne: ArtifactoryOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        type: "ACCESS_TOKEN",
        secretType: "Artifactory",
        secretValue: {
            match: { 
                api_key: "abcdef1234567890123456789012345678901234567890123456789012345678901234",
                url: "example.jfrog.io"
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

    const mockArtifactoryOccurrenceTwo = {
        ...mockArtifactoryOccurrenceOne,
        fingerprint: "fp2"
    };

    const mockArtifactoryOccurrenceThree = {
        ...mockArtifactoryOccurrenceOne,
        fingerprint: "fp3"
    };

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockArtifactoryOccurrenceOne]);
    const mockOccurrencesTwo: Set<Occurrence> = new Set([mockArtifactoryOccurrenceOne, mockArtifactoryOccurrenceTwo]);
    const mockOccurrencesThree: Set<Occurrence> = new Set([mockArtifactoryOccurrenceOne, mockArtifactoryOccurrenceTwo, mockArtifactoryOccurrenceThree]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrencesOne.size,
            occurrences: mockOccurrencesOne,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Artifactory",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678901234567890123456789012345678901234",
                    url: "example.jfrog.io"
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
            secretType: "Artifactory",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678901234567890123456789012345678901234",
                    url: "example.jfrog.io"
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
            secretType: "Artifactory",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678901234567890123456789012345678901234",
                    url: "example.jfrog.io"
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
            secretType: "Artifactory",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678901234567890123456789012345678901234",
                    url: "example.jfrog.io"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "failed_to_check"
            }
        },
    ];

    test('should mark finding as invalid when Artifactory credentials validation fails', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateArtifactoryCredentials.mockResolvedValue({ valid: false, error: 'Invalid token' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should mark finding as valid when Artifactory credentials validation succeeds and finding was previously invalid', async () => {
        const mockFinding = mockFindings[1];
        const mockExistingFindings = [mockFindings[0], mockFinding, mockFindings[2]];

        mockValidateArtifactoryCredentials.mockResolvedValue({ valid: true, error: '', url: 'https://example.jfrog.io' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when Artifactory credentials are valid and finding is already valid', async () => {
        const mockFinding = mockFindings[0];
        const mockExistingFindings = [mockFindings[1], mockFinding, mockFindings[2]];

        mockValidateArtifactoryCredentials.mockResolvedValue({ valid: true, error: '', url: 'https://example.jfrog.io' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' },
            mockFindings[2]
        ]);
    });

    test('should update timestamp when Artifactory credentials are valid and finding has unknown validity', async () => {
        const mockFinding = mockFindings[2];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFinding];

        mockValidateArtifactoryCredentials.mockResolvedValue({ valid: true, error: '', url: 'https://example.jfrog.io' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should update timestamp when Artifactory credentials are valid and finding has failed_to_check validity', async () => {
        const mockFinding = mockFindings[3];
        const mockExistingFindings = [mockFindings[0], mockFindings[1], mockFindings[2], mockFinding];

        mockValidateArtifactoryCredentials.mockResolvedValue({ valid: true, error: '', url: 'https://example.jfrog.io' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            mockFindings[0],
            mockFindings[1],
            mockFindings[2],
            { ...mockFinding, validity: 'valid', validatedAt: '2025-05-30T12:00:00.000Z' }
        ]);
    });

    test('should handle multiple Artifactory occurrences and break on first invalid', async () => {
        const mockFinding = {
            ...mockFindings[0],
            secretValue: {
                occurrence1: { 
                    api_key: "abcdef1234567890123456789012345678901234567890123456789012345678901234",
                    url: "example.jfrog.io"
                },
                occurrence2: { 
                    api_key: "zyxwvu9876543210987654321098765432109876543210987654321098765432109876",
                    url: "example2.jfrog.io"
                }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateArtifactoryCredentials
            .mockResolvedValueOnce({ valid: false, error: 'Invalid token' })
            .mockResolvedValueOnce({ valid: true, error: '', url: 'https://example2.jfrog.io' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
        );

        // The stored finding should have the modified validity and timestamp
        const expectedStoredFindings = [...mockExistingFindings];
        expectedStoredFindings[0] = { ...expectedStoredFindings[0], validity: 'invalid', validatedAt: '2025-05-30T12:00:00.000Z' };

        expect(mockStoreFindings).toHaveBeenCalledWith(expectedStoredFindings);
    });

    test('should handle multiple Artifactory occurrences when all are valid', async () => {
        const mockFinding = {
            ...mockFindings[0],
            secretValue: {
                occurrence1: { 
                    api_key: "abcdef1234567890123456789012345678901234567890123456789012345678901234",
                    url: "example.jfrog.io"
                },
                occurrence2: { 
                    api_key: "zyxwvu9876543210987654321098765432109876543210987654321098765432109876",
                    url: "example2.jfrog.io"
                }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateArtifactoryCredentials
            .mockResolvedValueOnce({ valid: true, error: '', url: 'https://example.jfrog.io' })
            .mockResolvedValueOnce({ valid: true, error: '', url: 'https://example2.jfrog.io' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledTimes(2); // Should check both occurrences when valid (no break in else clause)
        expect(mockValidateArtifactoryCredentials).toHaveBeenNthCalledWith(1, 
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
        );
        expect(mockValidateArtifactoryCredentials).toHaveBeenNthCalledWith(2, 
            'zyxwvu9876543210987654321098765432109876543210987654321098765432109876',
            'example2.jfrog.io'
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
            secretType: 'Artifactory',
            secretValue: {}
        };

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).not.toHaveBeenCalled();
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
            secretType: 'Artifactory',
            secretValue: {
                match: { api_key: undefined, url: "example.jfrog.io" }
            }
        };

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle finding at index 0 in existing findings array when validation fails', async () => {
        const mockFinding = mockFindings[0]; // This finding has validity: "valid"
        const mockExistingFindings = [mockFinding, mockFindings[1], mockFindings[2]]; // mockFinding at index 0

        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
        
        // Reset all mocks to ensure clean state
        mockValidateArtifactoryCredentials.mockReset();
        mockRetrieveFindings.mockReset();
        mockStoreFindings.mockReset();
        
        mockValidateArtifactoryCredentials.mockResolvedValue({ valid: false, error: 'Invalid token' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
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
                occurrence1: { api_key: null, url: "example.jfrog.io" }, // No api_key
                occurrence2: { 
                    api_key: "abcdef1234567890123456789012345678901234567890123456789012345678901234",
                    url: "example.jfrog.io"
                }
            }
        };
        const mockExistingFindings = [mockFinding, ...mockFindings.slice(1)];

        mockValidateArtifactoryCredentials.mockResolvedValue({ valid: true, error: '', url: 'https://example.jfrog.io' });
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);

        await artifactoryValidityHelper(mockFinding);

        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateArtifactoryCredentials).toHaveBeenCalledWith(
            'abcdef1234567890123456789012345678901234567890123456789012345678901234',
            'example.jfrog.io'
        );
        expect(mockStoreFindings).toHaveBeenCalled();
    });
});