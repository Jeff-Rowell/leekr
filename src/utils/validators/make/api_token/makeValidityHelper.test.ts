import { makeValidityHelper } from './makeValidityHelper';
import { validateMakeApiToken } from './make';
import { retrieveFindings, storeFindings } from '../../../helpers/common';
import { Finding } from '../../../../types/findings.types';

jest.mock('./make');
jest.mock('../../../helpers/common');

describe('makeValidityHelper', () => {
    const mockValidateMakeApiToken = validateMakeApiToken as jest.MockedFunction<typeof validateMakeApiToken>;
    const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
    const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        secretType: 'Make',
        occurrences: new Set(),
        numOccurrences: 1,
        secretValue: {
            'test-key': {
                api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
            }
        },
        validity: 'unknown',
        validatedAt: undefined
    };

    const mockExistingFindings: Finding[] = [
        {
            ...mockFinding,
            validity: 'unknown'
        }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);
        mockStoreFindings.mockResolvedValue(undefined);
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('when validation is successful', () => {
        it('should mark finding as valid when token is valid and current status is unknown', async () => {
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            await makeValidityHelper(mockFinding);

            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    fingerprint: 'test-fingerprint',
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ]);
        });

        it('should mark finding as valid when token is valid and current status is valid', async () => {
            const validFinding = { ...mockFinding, validity: 'valid' as const };
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            await makeValidityHelper(validFinding);

            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    fingerprint: 'test-fingerprint',
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ]);
        });

        it('should reactivate finding when token becomes valid after being invalid', async () => {
            const invalidFinding = { ...mockFinding, validity: 'invalid' as const };
            const invalidExistingFindings = [{ ...mockFinding, validity: 'invalid' as const }];
            mockRetrieveFindings.mockResolvedValue(invalidExistingFindings);
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            await makeValidityHelper(invalidFinding);

            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    fingerprint: 'test-fingerprint',
                    validity: 'valid',
                    validatedAt: expect.any(String)
                })
            ]);
        });
    });

    describe('when validation fails', () => {
        it('should mark finding as invalid when token validation fails', async () => {
            mockValidateMakeApiToken.mockResolvedValue({ valid: false });

            await makeValidityHelper(mockFinding);

            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    fingerprint: 'test-fingerprint',
                    validity: 'invalid',
                    validatedAt: expect.any(String)
                })
            ]);
        });

        it('should mark finding as invalid when token validation fails with error', async () => {
            mockValidateMakeApiToken.mockResolvedValue({ valid: false, error: 'Network error' });

            await makeValidityHelper(mockFinding);

            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    fingerprint: 'test-fingerprint',
                    validity: 'invalid',
                    validatedAt: expect.any(String)
                })
            ]);
        });
    });

    describe('edge cases', () => {
        it('should handle finding with multiple secret values', async () => {
            const multiValueFinding: Finding = {
                ...mockFinding,
                secretValue: {
                    'key1': {
                        api_token: 'bbb49d50-239a-4609-9569-63ea15ef0997'
                    },
                    'key2': {
                        api_token: '924ee925-f461-466a-99bc-63cfce078057'
                    }
                }
            };
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            await makeValidityHelper(multiValueFinding);

            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect(mockValidateMakeApiToken).toHaveBeenCalledTimes(1);
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalled();
        });

        it('should handle finding not found in existing findings', async () => {
            mockRetrieveFindings.mockResolvedValue([]);
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            await makeValidityHelper(mockFinding);

            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).not.toHaveBeenCalled();
        });

        it('should handle different fingerprint in existing findings', async () => {
            const differentFinding = { ...mockFinding, fingerprint: 'different-fingerprint' };
            mockRetrieveFindings.mockResolvedValue([differentFinding]);
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            await makeValidityHelper(mockFinding);

            expect(mockValidateMakeApiToken).toHaveBeenCalledWith('bbb49d50-239a-4609-9569-63ea15ef0997');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).not.toHaveBeenCalled();
        });

        it('should update timestamp format correctly', async () => {
            const mockDate = new Date('2023-01-01T00:00:00.000Z');
            jest.spyOn(global, 'Date').mockImplementation(() => mockDate);
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            await makeValidityHelper(mockFinding);

            expect(mockStoreFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    fingerprint: 'test-fingerprint',
                    validity: 'valid',
                    validatedAt: '2023-01-01T00:00:00.000Z'
                })
            ]);

            (global.Date as any).mockRestore();
        });
    });

    describe('async behavior', () => {
        it('should handle retrieveFindings promise correctly', async () => {
            let resolveFindings: (value: Finding[]) => void;
            const findingsPromise = new Promise<Finding[]>((resolve) => {
                resolveFindings = resolve;
            });
            mockRetrieveFindings.mockReturnValue(findingsPromise);
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            const helperPromise = makeValidityHelper(mockFinding);
            
            setTimeout(() => resolveFindings!(mockExistingFindings), 10);
            
            await helperPromise;
            
            // Give time for the async then to execute
            await new Promise(resolve => setTimeout(resolve, 50));

            expect(mockStoreFindings).toHaveBeenCalled();
        });

        it('should handle storeFindings promise correctly', async () => {
            let resolveStore: () => void;
            const storePromise = new Promise<void>((resolve) => {
                resolveStore = resolve;
            });
            mockStoreFindings.mockReturnValue(storePromise);
            mockValidateMakeApiToken.mockResolvedValue({ valid: true });

            const helperPromise = makeValidityHelper(mockFinding);
            
            setTimeout(() => resolveStore!(), 10);
            
            await helperPromise;

            expect(mockStoreFindings).toHaveBeenCalled();
        });
    });
});