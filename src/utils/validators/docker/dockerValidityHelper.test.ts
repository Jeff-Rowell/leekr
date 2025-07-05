import { dockerValidityHelper } from './dockerValidityHelper';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateDockerCredentials } from './docker';
import { Finding, ValidityStatus, Occurrence, SourceContent } from '../../../types/findings.types';

// Mock the dependencies
jest.mock('../../helpers/common');
jest.mock('./docker');

const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;
const mockValidateDockerCredentials = validateDockerCredentials as jest.MockedFunction<typeof validateDockerCredentials>;

describe('dockerValidityHelper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    const createMockFinding = (validity: ValidityStatus = 'unknown'): Finding => ({
        fingerprint: 'test-fingerprint',
        secretType: 'Docker',
        secretValue: {
            match: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0',
                username: 'test',
                password: 'test',
                email: 'test@example.com'
            },
            validity: validity,
            validatedAt: new Date().toISOString()
        },
        validity: validity,
        validatedAt: new Date().toISOString(),
        numOccurrences: 1,
        occurrences: new Set<Occurrence>()
    });

    test('should mark finding as invalid when validation fails', async () => {
        const finding = createMockFinding();
        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: false,
            type: 'REGISTRY',
            error: 'Invalid credentials'
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(JSON.stringify({
            auths: {
                'registry.example.com': {
                    auth: 'dGVzdDp0ZXN0',
                    username: 'test',
                    password: 'test',
                    email: 'test@example.com'
                }
            }
        }));

        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'invalid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    test('should mark finding as valid when validation succeeds and was previously invalid', async () => {
        const finding = createMockFinding('invalid');
        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    test('should update timestamp when finding is still valid', async () => {
        const finding = createMockFinding('valid');
        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    test('should skip occurrences without proper match data', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                // Missing required fields
                invalidField: 'invalid',
                validity: 'unknown',
                validatedAt: new Date().toISOString()
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle missing registry in data', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                match: {
                    auth: 'dGVzdDp0ZXN0'
                    // Missing registry
                },
                validity: 'unknown',
                validatedAt: new Date().toISOString()
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle missing auth in data', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                match: {
                    registry: 'registry.example.com'
                    // Missing auth
                },
                validity: 'unknown',
                validatedAt: new Date().toISOString()
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle multiple occurrences and stop on first invalid', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                occurrence1: {
                    registry: 'registry1.example.com',
                    auth: 'dGVzdDE6dGVzdDE='
                },
                occurrence2: {
                    registry: 'registry2.example.com',
                    auth: 'dGVzdDI6dGVzdDI='
                }
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 2,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        // First validation fails
        mockValidateDockerCredentials.mockResolvedValue({
            valid: false,
            type: 'REGISTRY',
            error: 'Invalid credentials'
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        // Should only validate once (stops on first invalid)
        expect(mockValidateDockerCredentials).toHaveBeenCalledTimes(1);
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                validity: 'invalid'
            })
        ]);
    });

    test('should continue to next occurrence if first validation succeeds', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                occurrence1: {
                    registry: 'registry1.example.com',
                    auth: 'dGVzdDE6dGVzdDE='
                },
                occurrence2: {
                    registry: 'registry2.example.com',
                    auth: 'dGVzdDI6dGVzdDI='
                },
                validity: 'unknown',
                validatedAt: new Date().toISOString()
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 2,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        // First validation succeeds, so should continue but break after first valid
        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        // Should validate first occurrence only (breaks on valid)
        expect(mockValidateDockerCredentials).toHaveBeenCalledTimes(1);
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                validity: 'valid'
            })
        ]);
    });

    test('should handle finding not found in existing findings', async () => {
        const finding = createMockFinding();
        const existingFindings: Finding[] = []; // Empty array

        mockValidateDockerCredentials.mockResolvedValue({
            valid: false,
            type: 'REGISTRY',
            error: 'Invalid credentials'
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockRetrieveFindings).toHaveBeenCalled();
        // storeFindings should still be called even with empty array
        expect(mockStoreFindings).toHaveBeenCalledWith([]);
    });

    test('should construct proper auth config JSON', async () => {
        const finding = createMockFinding();
        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        const expectedAuthConfig = JSON.stringify({
            auths: {
                'registry.example.com': {
                    auth: 'dGVzdDp0ZXN0',
                    username: 'test',
                    password: 'test',
                    email: 'test@example.com'
                }
            }
        });

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(expectedAuthConfig);
    });

    test('should handle missing optional fields in data', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0'
                // Missing username, password, email
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        const expectedAuthConfig = JSON.stringify({
            auths: {
                'registry.example.com': {
                    auth: 'dGVzdDp0ZXN0'
                }
            }
        });

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(expectedAuthConfig);
    });

    test('should handle flat structure with all optional fields defined', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0',
                username: 'testuser',
                password: 'testpass',
                email: 'test@example.com'
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        const expectedAuthConfig = JSON.stringify({
            auths: {
                'registry.example.com': {
                    auth: 'dGVzdDp0ZXN0',
                    username: 'testuser',
                    password: 'testpass',
                    email: 'test@example.com'
                }
            }
        });

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(expectedAuthConfig);
    });

    test('should handle nested structure with direct registry/auth format', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                occurrence1: {
                    registry: 'registry1.example.com',
                    auth: 'dGVzdDE6dGVzdDE=',
                    username: 'test1',
                    password: 'test1'
                },
                validity: 'unknown',
                validatedAt: new Date().toISOString()
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        const expectedAuthConfig = JSON.stringify({
            auths: {
                'registry1.example.com': {
                    auth: 'dGVzdDE6dGVzdDE=',
                    username: 'test1',
                    password: 'test1'
                }
            }
        });

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(expectedAuthConfig);
    });

    test('should handle nested structure with optional fields undefined', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                occurrence1: {
                    registry: 'registry1.example.com',
                    auth: 'dGVzdDE6dGVzdDE='
                    // username, password, email are undefined
                },
                validity: 'unknown',
                validatedAt: new Date().toISOString()
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        const expectedAuthConfig = JSON.stringify({
            auths: {
                'registry1.example.com': {
                    auth: 'dGVzdDE6dGVzdDE='
                }
            }
        });

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(expectedAuthConfig);
    });

    test('should handle nested match object format with all fields', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                someKey: {
                    match: {
                        registry: 'registry.example.com',
                        auth: 'dGVzdDp0ZXN0',
                        username: 'test',
                        password: 'test',
                        email: 'test@example.com'
                    }
                },
                validity: 'unknown',
                validatedAt: new Date().toISOString()
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        const expectedAuthConfig = JSON.stringify({
            auths: {
                'registry.example.com': {
                    auth: 'dGVzdDp0ZXN0',
                    username: 'test',
                    password: 'test',
                    email: 'test@example.com'
                }
            }
        });

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(expectedAuthConfig);
    });

    test('should handle nested match object format with minimal fields', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                someKey: {
                    match: {
                        registry: 'registry.example.com',
                        auth: 'dGVzdDp0ZXN0'
                        // username, password, email are undefined
                    }
                },
                validity: 'unknown',
                validatedAt: new Date().toISOString()
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        const expectedAuthConfig = JSON.stringify({
            auths: {
                'registry.example.com': {
                    auth: 'dGVzdDp0ZXN0'
                }
            }
        });

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(expectedAuthConfig);
    });

    test('should handle flat structure with some undefined optional fields', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0',
                username: 'testuser',
                password: undefined, // Explicitly undefined
                email: 'test@example.com'
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [finding];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        const expectedAuthConfig = JSON.stringify({
            auths: {
                'registry.example.com': {
                    auth: 'dGVzdDp0ZXN0',
                    username: 'testuser',
                    email: 'test@example.com'
                }
            }
        });

        expect(mockValidateDockerCredentials).toHaveBeenCalledWith(expectedAuthConfig);
    });

    test('should handle flat structure when finding is not in existing findings (lines 39-56)', async () => {
        const finding: Finding = {
            fingerprint: 'nonexistent-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0',
                username: 'test',
                password: 'test'
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        // Return empty findings array (finding not found)
        const existingFindings: Finding[] = [];

        mockValidateDockerCredentials.mockResolvedValue({
            valid: false,
            type: 'REGISTRY',
            error: 'Invalid credentials'
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith(existingFindings); // Called with empty array
    });

    test('should handle flat structure when validation is invalid and finding not found (lines 39-45)', async () => {
        const finding: Finding = {
            fingerprint: 'missing-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0'
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        mockValidateDockerCredentials.mockResolvedValue({
            valid: false,
            type: 'REGISTRY',
            error: 'Invalid credentials'
        });

        mockRetrieveFindings.mockResolvedValue([]); // Finding not in existing findings

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([]); // Empty array since finding not found
    });

    test('should handle flat structure when validation passes but finding was previously invalid and not found (lines 46-53)', async () => {
        const finding: Finding = {
            fingerprint: 'missing-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0'
            },
            validity: 'invalid', // Previously invalid
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue([]); // Finding not in existing findings

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([]); // Empty array since finding not found
    });

    test('should handle flat structure when validation passes and finding not found in existing findings (lines 54-61)', async () => {
        const finding: Finding = {
            fingerprint: 'missing-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0'
            },
            validity: 'valid', // Still valid
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue([]); // Finding not in existing findings

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([]); // Empty array since finding not found
    });

    test('should handle flat structure when validation fails and finding is found in existing findings (lines 40-43)', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0'
            },
            validity: 'unknown',
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [{ ...finding }]; // Finding exists in array

        mockValidateDockerCredentials.mockResolvedValue({
            valid: false,
            type: 'REGISTRY',
            error: 'Invalid credentials'
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'invalid',
                validatedAt: expect.any(String)
            })
        ]);
    });

    test('should handle flat structure when validation passes and finding was previously invalid and found in existing findings (lines 48-51)', async () => {
        const finding: Finding = {
            fingerprint: 'test-fingerprint',
            secretType: 'Docker',
            secretValue: {
                registry: 'registry.example.com',
                auth: 'dGVzdDp0ZXN0'
            },
            validity: 'invalid', // Previously invalid
            validatedAt: new Date().toISOString(),
            numOccurrences: 1,
            occurrences: new Set<Occurrence>()
        };

        const existingFindings = [{ ...finding }]; // Finding exists in array

        mockValidateDockerCredentials.mockResolvedValue({
            valid: true,
            type: 'REGISTRY',
            error: ''
        });

        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await dockerValidityHelper(finding);

        expect(mockValidateDockerCredentials).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            expect.objectContaining({
                fingerprint: 'test-fingerprint',
                validity: 'valid',
                validatedAt: expect.any(String)
            })
        ]);
    });
});