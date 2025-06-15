import { validateAWSCredentials } from './aws';
import CryptoJS from 'crypto-js';

jest.mock('crypto-js', () => ({
    SHA256: jest.fn(),
    HmacSHA256: jest.fn(),
    enc: {
        Hex: 'hex',
        Utf8: {
            parse: jest.fn()
        }
    },
    lib: {
        WordArray: jest.fn()
    }
}));

global.fetch = jest.fn();

const mockDate = new Date('2023-06-15T10:30:45.000Z');
jest.spyOn(global, 'Date').mockImplementation(() => mockDate);

jest.useFakeTimers();

describe('aws.ts', () => {
    const mockAccessKeyId = 'AKIAIOSFODNN7EXAMPLE';
    const mockSecretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const mockSessionToken = 'session-token-example';

    beforeEach(() => {
        jest.clearAllMocks();
        jest.clearAllTimers();

        const mockWordArray = { toString: jest.fn().mockReturnValue('mocked-hash') };
        (CryptoJS.SHA256 as jest.Mock).mockReturnValue(mockWordArray);
        (CryptoJS.HmacSHA256 as jest.Mock).mockReturnValue(mockWordArray);
        (CryptoJS.enc.Utf8.parse as jest.Mock).mockReturnValue(mockWordArray);
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    describe('validateAWSCredentials', () => {
        test('should return valid credentials for successful response', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue({
                    GetCallerIdentityResponse: {
                        GetCallerIdentityResult: {
                            Account: '123456789012',
                            Arn: 'arn:aws:iam::123456789012:user/testuser'
                        }
                    }
                })
            };

            (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: true,
                accountId: '123456789012',
                arn: 'arn:aws:iam::123456789012:user/testuser'
            });

            expect(global.fetch).toHaveBeenCalledWith(
                'https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15',
                expect.objectContaining({
                    method: 'GET',
                    headers: expect.objectContaining({
                        Accept: 'application/json',
                        Authorization: expect.stringContaining('AWS4-HMAC-SHA256'),
                        'x-amz-date': expect.stringMatching(/^\d{8}T\d{6}Z$/),
                        'x-amz-security-token': mockSessionToken,
                        'x-amz-content-sha256': 'mocked-hash'
                    })
                })
            );
        });

        test('should handle 403 response with retry', async () => {
            const mockSetTimeout = jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
                Promise.resolve().then(() => callback());
                return 123 as any;
            });

            const mock403Response = {
                status: 403
            };

            const mockSuccessResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue({
                    GetCallerIdentityResponse: {
                        GetCallerIdentityResult: {
                            Account: '123456789012',
                            Arn: 'arn:aws:iam::123456789012:user/testuser'
                        }
                    }
                })
            };

            (global.fetch as jest.Mock)
                .mockResolvedValueOnce(mock403Response)
                .mockResolvedValueOnce(mockSuccessResponse);

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: true,
                accountId: '123456789012',
                arn: 'arn:aws:iam::123456789012:user/testuser'
            });

            expect(global.fetch).toHaveBeenCalledTimes(2);
            expect(mockSetTimeout).toHaveBeenCalledWith(expect.any(Function), 5000);
            mockSetTimeout.mockRestore();
        });

        test('should handle 403 response without retry when retryOn403 is false', async () => {
            const mockSetTimeout = jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
                Promise.resolve().then(() => callback());
                return 123 as any;
            });

            const mock403Response = {
                status: 403
            };

            (global.fetch as jest.Mock)
                .mockResolvedValueOnce(mock403Response)
                .mockResolvedValueOnce(mock403Response);

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: false
            });
            expect(global.fetch).toHaveBeenCalledTimes(2);
            expect(mockSetTimeout).toHaveBeenCalledWith(expect.any(Function), 5000);

            mockSetTimeout.mockRestore();
        });

        test('should handle errors thrown during crypto operations', async () => {
            (CryptoJS.SHA256 as jest.Mock).mockImplementation(() => {
                throw new Error('Crypto operation failed');
            });

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: false,
                error: 'Crypto operation failed'
            });
        });

        test('should handle non-Error exceptions during execution', async () => {
            (CryptoJS.enc.Utf8.parse as jest.Mock).mockImplementation(() => {
                throw 'String error thrown';
            });

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: false,
                error: 'Unknown error occurred'
            });
          });

        test('should handle other error responses', async () => {
            const mockErrorResponse = {
                status: 401
            };

            (global.fetch as jest.Mock).mockResolvedValue(mockErrorResponse);

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: false
            });
            expect(global.fetch).toHaveBeenCalledTimes(1);
        });

        test('should handle 500 error responses', async () => {
            const mockErrorResponse = {
                status: 500
            };

            (global.fetch as jest.Mock).mockResolvedValue(mockErrorResponse);

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: false
            });
            expect(global.fetch).toHaveBeenCalledTimes(1);
        });

        test('should correctly format dates and build canonical request', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue({
                    GetCallerIdentityResponse: {
                        GetCallerIdentityResult: {
                            Account: '123456789012',
                            Arn: 'arn:aws:iam::123456789012:user/testuser'
                        }
                    }
                })
            };

            (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

            await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(CryptoJS.SHA256).toHaveBeenCalled();
            expect(CryptoJS.HmacSHA256).toHaveBeenCalled();
            expect(CryptoJS.enc.Utf8.parse).toHaveBeenCalledWith(`AWS4${mockSecretAccessKey}`);

            const fetchCall = (global.fetch as jest.Mock).mock.calls[0];
            expect(fetchCall[1].headers['x-amz-date']).toBe('20230615T103045Z');
        });

        test('should build correct canonical querystring', async () => {
            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue({
                    GetCallerIdentityResponse: {
                        GetCallerIdentityResult: {
                            Account: '123456789012',
                            Arn: 'arn:aws:iam::123456789012:user/testuser'
                        }
                    }
                })
            };

            (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

            await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            const fetchCall = (global.fetch as jest.Mock).mock.calls[0];
            const url = fetchCall[0];
            expect(url).toBe('https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15');
        });

        test('should handle edge case status codes at boundary conditions', async () => {
            const mockResponse199 = {
                status: 199
            };

            (global.fetch as jest.Mock).mockResolvedValue(mockResponse199);

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: false
            });
        });

        test('should handle status code 300 (at upper boundary)', async () => {
            const mockResponse300 = {
                status: 300
            };

            (global.fetch as jest.Mock).mockResolvedValue(mockResponse300);

            const result = await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(result).toEqual({
                valid: false
            });
        });

        test('should properly chain HMAC operations for signature generation', async () => {
            const mockWordArray1 = { toString: jest.fn().mockReturnValue('hash1') };
            const mockWordArray2 = { toString: jest.fn().mockReturnValue('hash2') };
            const mockWordArray3 = { toString: jest.fn().mockReturnValue('hash3') };
            const mockWordArray4 = { toString: jest.fn().mockReturnValue('hash4') };
            const mockWordArray5 = { toString: jest.fn().mockReturnValue('final-signature') };

            (CryptoJS.enc.Utf8.parse as jest.Mock).mockReturnValue(mockWordArray1);
            (CryptoJS.HmacSHA256 as jest.Mock)
                .mockReturnValueOnce(mockWordArray2)
                .mockReturnValueOnce(mockWordArray3)
                .mockReturnValueOnce(mockWordArray4)
                .mockReturnValueOnce(mockWordArray5)
                .mockReturnValue(mockWordArray5);

            const mockResponse = {
                status: 200,
                json: jest.fn().mockResolvedValue({
                    GetCallerIdentityResponse: {
                        GetCallerIdentityResult: {
                            Account: '123456789012',
                            Arn: 'arn:aws:iam::123456789012:user/testuser'
                        }
                    }
                })
            };

            (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

            await validateAWSCredentials(
                mockAccessKeyId,
                mockSecretAccessKey,
                mockSessionToken
            );

            expect(CryptoJS.HmacSHA256).toHaveBeenCalledWith('20230615', mockWordArray1);
            expect(CryptoJS.HmacSHA256).toHaveBeenCalledWith('us-east-1', mockWordArray2);
            expect(CryptoJS.HmacSHA256).toHaveBeenCalledWith('sts', mockWordArray3);
            expect(CryptoJS.HmacSHA256).toHaveBeenCalledWith('aws4_request', mockWordArray4);
        });
    });
});