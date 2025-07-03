import { gcpValidityHelper } from './gcpValidityHelper';
import { validateGcpCredentials } from './gcp';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

// Mock dependencies
jest.mock('./gcp');
jest.mock('../../helpers/common');

const mockValidateGcpCredentials = validateGcpCredentials as jest.MockedFunction<typeof validateGcpCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('gcpValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    const validServiceAccountKey = JSON.stringify({
        type: "service_account",
        project_id: "test-project",
        private_key_id: "test123",
        private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
        client_email: "test@test-project.iam.gserviceaccount.com",
        client_id: "123456789",
        auth_uri: "https://accounts.google.com/o/oauth2/auth",
        token_uri: "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
        client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/test"
    });

    const mockFinding: Finding = {
        secretType: 'Google Cloud Platform',
        fingerprint: 'test-fingerprint',
        validity: 'unknown',
        numOccurrences: 1,
        occurrences: new Set([]),
        secretValue: {
            occurrence1: {
                service_account_key: validServiceAccountKey
            }
        } as any
    };

    const mockExistingFindings: Finding[] = [
        {
            ...mockFinding,
            secretType: 'Google Cloud Platform',
            fingerprint: 'test-fingerprint',
            validity: 'unknown',
            numOccurrences: 1,
            occurrences: new Set([]),
            secretValue: {
                occurrence1: {
                    service_account_key: validServiceAccountKey
                }
            } as any
        }
    ];

    test('should mark finding as invalid when validation fails', async () => {
        mockValidateGcpCredentials.mockResolvedValueOnce({
            valid: false,
            type: 'unknown',
            error: 'Invalid credentials'
        });

        mockRetrieveFindings.mockResolvedValueOnce(mockExistingFindings);

        await gcpValidityHelper(mockFinding);

        expect(mockValidateGcpCredentials).toHaveBeenCalledWith(validServiceAccountKey);
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    test('should mark previously invalid finding as valid when validation succeeds', async () => {
        const invalidFinding = { ...mockFinding, validity: 'invalid' as const };
        const invalidExistingFindings = [{ ...mockExistingFindings[0], validity: 'invalid' as const }];

        mockValidateGcpCredentials.mockResolvedValueOnce({
            valid: true,
            type: 'SERVICE_ACCOUNT',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValueOnce(invalidExistingFindings);

        await gcpValidityHelper(invalidFinding);

        expect(mockValidateGcpCredentials).toHaveBeenCalledWith(validServiceAccountKey);
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...invalidExistingFindings[0],
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    test('should update timestamp for valid finding that remains valid', async () => {
        const validFinding = { ...mockFinding, validity: 'valid' as const };
        const validExistingFindings = [{ ...mockExistingFindings[0], validity: 'valid' as const }];

        mockValidateGcpCredentials.mockResolvedValueOnce({
            valid: true,
            type: 'SERVICE_ACCOUNT',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValueOnce(validExistingFindings);

        await gcpValidityHelper(validFinding);

        expect(mockValidateGcpCredentials).toHaveBeenCalledWith(validServiceAccountKey);
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...validExistingFindings[0],
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    test('should skip occurrence without service_account_key', async () => {
        const findingWithoutKey: Finding = {
            ...mockFinding,
            secretValue: {
                occurrence1: {
                    // No service_account_key field
                }
            } as any
        };

        await gcpValidityHelper(findingWithoutKey);

        expect(mockValidateGcpCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle multiple occurrences and stop on first invalid', async () => {
        const findingWithMultipleOccurrences: Finding = {
            ...mockFinding,
            secretValue: {
                occurrence1: {
                    service_account_key: validServiceAccountKey
                },
                occurrence2: {
                    service_account_key: validServiceAccountKey
                }
            } as any
        };

        mockValidateGcpCredentials.mockResolvedValueOnce({
            valid: false,
            type: 'unknown',
            error: 'Invalid credentials'
        });

        mockRetrieveFindings.mockResolvedValueOnce(mockExistingFindings);

        await gcpValidityHelper(findingWithMultipleOccurrences);

        expect(mockValidateGcpCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateGcpCredentials).toHaveBeenCalledWith(validServiceAccountKey);
    });

    test('should handle multiple occurrences and stop on first valid reactivation', async () => {
        const invalidFinding: Finding = {
            ...mockFinding,
            validity: 'invalid',
            secretValue: {
                occurrence1: {
                    service_account_key: validServiceAccountKey
                },
                occurrence2: {
                    service_account_key: validServiceAccountKey
                }
            } as any
        };

        const invalidExistingFindings = [{ ...mockExistingFindings[0], validity: 'invalid' as const }];

        mockValidateGcpCredentials.mockResolvedValueOnce({
            valid: true,
            type: 'SERVICE_ACCOUNT',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValueOnce(invalidExistingFindings);

        await gcpValidityHelper(invalidFinding);

        expect(mockValidateGcpCredentials).toHaveBeenCalledTimes(1);
        expect(mockValidateGcpCredentials).toHaveBeenCalledWith(validServiceAccountKey);
    });
});