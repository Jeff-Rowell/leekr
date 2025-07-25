import { makeMcpValidityHelper } from './makeMcpValidityHelper';
import { validateMakeMcpToken } from './make';
import { retrieveFindings, storeFindings } from '../../../helpers/common';
import { Finding } from '../../../../types/findings.types';

jest.mock('./make');
jest.mock('../../../helpers/common');

describe('makeMcpValidityHelper', () => {
    const mockValidateMakeMcpToken = validateMakeMcpToken as jest.MockedFunction<typeof validateMakeMcpToken>;
    const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
    const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        secretType: 'Make MCP',
        secretValue: {
            match: {
                mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
            }
        },
        occurrences: new Set(),
        numOccurrences: 1,
        validity: 'unknown' as const
    };

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue([
            {
                ...mockFinding,
                fingerprint: 'test-fingerprint'
            }
        ]);
    });

    describe('when validation is successful', () => {
        it('should mark finding as valid when token is valid and current status is unknown', async () => {
            mockValidateMakeMcpToken.mockResolvedValue({ valid: true });

            await makeMcpValidityHelper(mockFinding);

            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
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
            mockValidateMakeMcpToken.mockResolvedValue({ valid: true });

            await makeMcpValidityHelper(validFinding);

            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
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
            mockValidateMakeMcpToken.mockResolvedValue({ valid: true });

            await makeMcpValidityHelper(invalidFinding);

            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
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
            mockValidateMakeMcpToken.mockResolvedValue({ valid: false });

            await makeMcpValidityHelper(mockFinding);

            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
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
            mockValidateMakeMcpToken.mockResolvedValue({ valid: false, error: 'Network error' });

            await makeMcpValidityHelper(mockFinding);

            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
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
            const findingWithMultipleValues = {
                ...mockFinding,
                secretValue: {
                    match: {
                        mcp_token: '3b142ebf-e958-4aef-8551-befb27231818',
                        full_url: 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse'
                    },
                    otherMatch: {
                        mcp_token: 'd36fcd27-b5f2-4615-b8d7-d8a581d8d52b',
                        full_url: 'https://eu1.make.com/api/v1/u/d36fcd27-b5f2-4615-b8d7-d8a581d8d52b/sse'
                    }
                }
            };
            mockValidateMakeMcpToken.mockResolvedValue({ valid: true });

            await makeMcpValidityHelper(findingWithMultipleValues);

            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalled();
        });

        it('should handle finding not found in existing findings', async () => {
            mockRetrieveFindings.mockResolvedValue([]);
            mockValidateMakeMcpToken.mockResolvedValue({ valid: false });

            await makeMcpValidityHelper(mockFinding);

            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).not.toHaveBeenCalled();
        });

        it('should handle different fingerprint in existing findings', async () => {
            mockRetrieveFindings.mockResolvedValue([
                {
                    ...mockFinding,
                    fingerprint: 'different-fingerprint'
                }
            ]);
            mockValidateMakeMcpToken.mockResolvedValue({ valid: false });

            await makeMcpValidityHelper(mockFinding);

            expect(mockValidateMakeMcpToken).toHaveBeenCalledWith('https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231818/sse');
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).not.toHaveBeenCalled();
        });

        it('should update timestamp format correctly', async () => {
            mockValidateMakeMcpToken.mockResolvedValue({ valid: true });
            const isoStringRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

            await makeMcpValidityHelper(mockFinding);

            expect(mockStoreFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    validatedAt: expect.stringMatching(isoStringRegex)
                })
            ]);
        });
    });

    describe('async behavior', () => {
        it('should handle retrieveFindings promise correctly', async () => {
            let resolveRetrieve: (value: any) => void;
            const retrievePromise = new Promise((resolve) => {
                resolveRetrieve = resolve;
            });
            mockRetrieveFindings.mockReturnValue(retrievePromise as Promise<any>);
            mockValidateMakeMcpToken.mockResolvedValue({ valid: false });

            const helperPromise = makeMcpValidityHelper(mockFinding);

            setTimeout(() => {
                resolveRetrieve!([
                    {
                        ...mockFinding,
                        fingerprint: 'test-fingerprint'
                    }
                ]);
            }, 10);

            await helperPromise;
            
            await new Promise(resolve => setTimeout(resolve, 50));

            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalled();
        });

        it('should handle storeFindings promise correctly', async () => {
            let resolveStore: (value: any) => void;
            const storePromise = new Promise((resolve) => {
                resolveStore = resolve;
            });
            mockStoreFindings.mockReturnValue(storePromise as Promise<any>);
            mockValidateMakeMcpToken.mockResolvedValue({ valid: false });

            const helperPromise = makeMcpValidityHelper(mockFinding);

            setTimeout(() => {
                resolveStore!(undefined);
            }, 10);

            await helperPromise;

            expect(mockValidateMakeMcpToken).toHaveBeenCalled();
            expect(mockRetrieveFindings).toHaveBeenCalled();
            expect(mockStoreFindings).toHaveBeenCalled();
        });
    });
});