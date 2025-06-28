import { ApolloOccurrence } from 'src/types/apollo';
import { Finding, Occurrence } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateApolloCredentials } from './apollo';
import { apolloValidityHelper } from './apolloValidityHelper';

jest.mock('./apollo');
jest.mock('../../helpers/common');

const mockValidateApolloCredentials = validateApolloCredentials as jest.MockedFunction<typeof validateApolloCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('apolloValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-30T12:00:00.000Z');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    const mockApolloOccurrenceOne: ApolloOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        type: "API_KEY",
        secretType: "Apollo",
        secretValue: {
            match: { 
                api_key: "abcdefghij1234567890AB"
            }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23]
        },
        url: "https://foo.bar.com"
    };

    const mockApolloOccurrenceTwo: ApolloOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp2",
        type: "API_KEY",
        secretType: "Apollo",
        secretValue: {
            match: { 
                api_key: "xyztuvwxyz9876543210CD"
            }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 45,
            contentFilename: "Config.js",
            contentStartLineNum: 28,
            exactMatchNumbers: [33]
        },
        url: "https://foo.bar.com"
    };

    const mockFinding: Finding = {
        numOccurrences: 1,
        secretType: "Apollo",
        secretValue: {
            match: {
                api_key: "abcdefghij1234567890AB"
            }
        },
        validity: "unknown",
        fingerprint: "finding123",
        occurrences: new Set([mockApolloOccurrenceOne])
    };

    test('should mark finding as invalid when validation fails', async () => {
        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: false,
            error: 'Invalid Apollo API key'
        });

        const existingFindings = [mockFinding];
        mockRetrieveFindings.mockResolvedValueOnce(existingFindings);

        await apolloValidityHelper(mockFinding);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith("abcdefghij1234567890AB");
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockFinding,
                validity: "invalid",
                validatedAt: "2025-05-30T12:00:00.000Z"
            }
        ]);
    });

    test('should mark finding as valid when validation succeeds', async () => {
        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        const existingFindings = [mockFinding];
        mockRetrieveFindings.mockResolvedValueOnce(existingFindings);

        await apolloValidityHelper(mockFinding);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith("abcdefghij1234567890AB");
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockFinding,
                validity: "valid",
                validatedAt: "2025-05-30T12:00:00.000Z"
            }
        ]);
    });

    test('should mark previously invalid finding as valid when validation succeeds', async () => {
        const invalidFinding = { ...mockFinding, validity: "invalid" as const };
        
        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        const existingFindings = [invalidFinding];
        mockRetrieveFindings.mockResolvedValueOnce(existingFindings);

        await apolloValidityHelper(invalidFinding);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith("abcdefghij1234567890AB");
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...invalidFinding,
                validity: "valid",
                validatedAt: "2025-05-30T12:00:00.000Z"
            }
        ]);
    });

    test('should update timestamp when finding is still valid', async () => {
        const validFinding = { ...mockFinding, validity: "valid" as const };
        
        mockValidateApolloCredentials.mockResolvedValue({
            valid: true,
            error: ''
        });

        const existingFindings = [validFinding];
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await apolloValidityHelper(validFinding);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith("abcdefghij1234567890AB");
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...validFinding,
                validity: "valid",
                validatedAt: "2025-05-30T12:00:00.000Z"
            }
        ]);
    });

    test('should skip finding without api_key', async () => {
        const findingWithoutApiKey: Finding = {
            numOccurrences: 1,
            secretType: "Apollo",
            secretValue: {
                match: {}
            },
            validity: "unknown",
            fingerprint: "finding123",
            occurrences: new Set([])
        };

        await apolloValidityHelper(findingWithoutApiKey);

        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should skip finding without match object', async () => {
        const findingWithoutMatch: Finding = {
            numOccurrences: 1,
            secretType: "Apollo",
            secretValue: {},
            validity: "unknown",
            fingerprint: "finding123",
            occurrences: new Set([])
        };

        await apolloValidityHelper(findingWithoutMatch);

        expect(mockValidateApolloCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should return early when finding not found in storage', async () => {
        mockValidateApolloCredentials.mockResolvedValueOnce({
            valid: true,
            error: ''
        });

        // Mock empty findings array so the finding won't be found
        mockRetrieveFindings.mockResolvedValueOnce([]);

        await apolloValidityHelper(mockFinding);

        expect(mockValidateApolloCredentials).toHaveBeenCalledWith("abcdefghij1234567890AB");
        expect(mockRetrieveFindings).toHaveBeenCalled();
        // Should not call storeFindings since function returns early
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });
});