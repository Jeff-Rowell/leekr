import { paypalOAuthValidityHelper } from './paypalOAuthValidityHelper';
import { validatePayPalOAuthCredentials } from './paypal_oauth';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from 'src/types/findings.types';

jest.mock('./paypal_oauth');
jest.mock('../../helpers/common');

const mockValidatePayPalOAuthCredentials = validatePayPalOAuthCredentials as jest.MockedFunction<typeof validatePayPalOAuthCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('PayPal OAuth Validity Helper', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue([]);
    });

    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        numOccurrences: 1,
        secretType: 'PayPal OAuth',
        validity: 'unknown',
        validatedAt: '2023-01-01T00:00:00.000Z',
        secretValue: {
            match: {
                client_id: 'test-client-id',
                client_secret: 'test-client-secret'
            }
        },
        occurrences: new Set()
    };

    describe('paypalOAuthValidityHelper', () => {
        it('should mark finding as invalid when validation fails', async () => {
            mockValidatePayPalOAuthCredentials.mockResolvedValue({
                valid: false,
                error: 'Invalid credentials'
            });

            const existingFindings = [mockFinding];
            mockRetrieveFindings.mockResolvedValue(existingFindings);

            await paypalOAuthValidityHelper(mockFinding);

            expect(mockValidatePayPalOAuthCredentials).toHaveBeenCalledWith(
                'test-client-id',
                'test-client-secret'
            );
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                {
                    ...mockFinding,
                    validity: 'invalid',
                    validatedAt: expect.any(String)
                }
            ]);
        });

        it('should mark finding as valid when validation succeeds and current validity is invalid', async () => {
            mockValidatePayPalOAuthCredentials.mockResolvedValue({
                valid: true
            });

            const invalidFinding = { ...mockFinding, validity: 'invalid' as const };
            const existingFindings = [invalidFinding];
            mockRetrieveFindings.mockResolvedValue(existingFindings);

            await paypalOAuthValidityHelper(invalidFinding);

            expect(mockValidatePayPalOAuthCredentials).toHaveBeenCalledWith(
                'test-client-id',
                'test-client-secret'
            );
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                {
                    ...invalidFinding,
                    validity: 'valid',
                    validatedAt: expect.any(String)
                }
            ]);
        });

        it('should update timestamp when validation succeeds and current validity is valid', async () => {
            mockValidatePayPalOAuthCredentials.mockResolvedValue({
                valid: true
            });

            const validFinding = { ...mockFinding, validity: 'valid' as const };
            const existingFindings = [validFinding];
            mockRetrieveFindings.mockResolvedValue(existingFindings);

            await paypalOAuthValidityHelper(validFinding);

            expect(mockValidatePayPalOAuthCredentials).toHaveBeenCalledWith(
                'test-client-id',
                'test-client-secret'
            );
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                {
                    ...validFinding,
                    validity: 'valid',
                    validatedAt: expect.any(String)
                }
            ]);
        });

        it('should update timestamp when validation succeeds and current validity is unknown', async () => {
            mockValidatePayPalOAuthCredentials.mockResolvedValue({
                valid: true
            });

            const unknownFinding = { ...mockFinding, validity: 'unknown' as const };
            const existingFindings = [unknownFinding];
            mockRetrieveFindings.mockResolvedValue(existingFindings);

            await paypalOAuthValidityHelper(unknownFinding);

            expect(mockValidatePayPalOAuthCredentials).toHaveBeenCalledWith(
                'test-client-id',
                'test-client-secret'
            );
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                {
                    ...unknownFinding,
                    validity: 'valid',
                    validatedAt: expect.any(String)
                }
            ]);
        });

        it('should handle multiple occurrences in secret value', async () => {
            mockValidatePayPalOAuthCredentials.mockResolvedValueOnce({
                valid: false,
                error: 'Invalid credentials'
            });

            const multiValueFinding = {
                ...mockFinding,
                secretValue: {
                    match1: {
                        client_id: 'test-client-id-1',
                        client_secret: 'test-client-secret-1'
                    },
                    match2: {
                        client_id: 'test-client-id-2',
                        client_secret: 'test-client-secret-2'
                    }
                }
            };

            const existingFindings = [multiValueFinding];
            mockRetrieveFindings.mockResolvedValue(existingFindings);

            await paypalOAuthValidityHelper(multiValueFinding);

            expect(mockValidatePayPalOAuthCredentials).toHaveBeenCalledWith(
                'test-client-id-1',
                'test-client-secret-1'
            );
            expect(mockValidatePayPalOAuthCredentials).toHaveBeenCalledTimes(1);
        });

        it('should stop processing on first invalid result', async () => {
            mockValidatePayPalOAuthCredentials.mockResolvedValueOnce({
                valid: false,
                error: 'Invalid credentials'
            });

            const multiValueFinding = {
                ...mockFinding,
                secretValue: {
                    match1: {
                        client_id: 'test-client-id-1',
                        client_secret: 'test-client-secret-1'
                    },
                    match2: {
                        client_id: 'test-client-id-2',
                        client_secret: 'test-client-secret-2'
                    }
                }
            };

            const existingFindings = [multiValueFinding];
            mockRetrieveFindings.mockResolvedValue(existingFindings);

            await paypalOAuthValidityHelper(multiValueFinding);

            expect(mockValidatePayPalOAuthCredentials).toHaveBeenCalledTimes(1);
            expect(mockValidatePayPalOAuthCredentials).toHaveBeenCalledWith(
                'test-client-id-1',
                'test-client-secret-1'
            );
        });
    });
});