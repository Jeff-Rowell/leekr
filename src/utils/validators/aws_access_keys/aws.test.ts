import { STS } from '@aws-sdk/client-sts';
import { validateAWSCredentials } from './aws';

jest.mock('@aws-sdk/client-sts');

const mockSTS = {
    getCallerIdentity: jest.fn(),
};

const MockedSTS = STS as jest.MockedClass<typeof STS>;

beforeEach(() => {
    jest.clearAllMocks();
    MockedSTS.mockImplementation(() => mockSTS as any);
    jest.spyOn(console, 'error').mockImplementation(() => { });
});

afterEach(() => {
    (console.error as jest.Mock).mockRestore();
});

describe('validateAWSCredentials', () => {
    test('should return valid credentials with account info when STS call succeeds', async () => {
        const mockResponse = {
            Account: '123456789012',
            Arn: 'arn:aws:iam::123456789012:user/testuser',
            UserId: 'USER_ID',
        };

        mockSTS.getCallerIdentity.mockResolvedValue(mockResponse);

        const result = await validateAWSCredentials('ACCESS_KEY', 'SECRET_KEY');

        expect(result).toEqual({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/testuser',
        });

        expect(MockedSTS).toHaveBeenCalledWith({
            credentials: {
                accessKeyId: 'ACCESS_KEY',
                secretAccessKey: 'SECRET_KEY',
            },
            region: 'us-east-1',
        });

        expect(mockSTS.getCallerIdentity).toHaveBeenCalledWith({});
    });

    test('should trim whitespace from credentials', async () => {
        const mockResponse = {
            Account: '123456789012',
            Arn: 'arn:aws:iam::123456789012:user/testuser',
            UserId: 'ACCESS_KEY',
        };

        mockSTS.getCallerIdentity.mockResolvedValue(mockResponse);

        const result = await validateAWSCredentials('  ACCESS_KEY  ', '  SECRET_KEY  ');

        expect(result).toEqual({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/testuser',
        });

        expect(MockedSTS).toHaveBeenCalledWith({
            credentials: {
                accessKeyId: 'ACCESS_KEY',
                secretAccessKey: 'SECRET_KEY',
            },
            region: 'us-east-1',
        });
    });

    test('should return invalid when InvalidClientTokenId error occurs', async () => {
        const error = new Error('The security token included in the request is invalid.');
        error.name = 'InvalidClientTokenId';

        mockSTS.getCallerIdentity.mockRejectedValue(error);

        const result = await validateAWSCredentials('INVALID_KEY', 'INVALID_SECRET');

        expect(result).toEqual({
            valid: false,
            accountId: '',
            arn: '',
        });
    });

    test('should retry once on SignatureDoesNotMatch error then return invalid', async () => {
        const error = new Error('The request signature we calculated does not match the signature you provided.');
        error.name = 'SignatureDoesNotMatch';

        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
            callback();
            return {} as NodeJS.Timeout;
        });

        mockSTS.getCallerIdentity
            .mockRejectedValueOnce(error)
            .mockRejectedValueOnce(error);

        const result = await validateAWSCredentials('ACCESS_KEY', 'WRONG_SECRET');

        expect(result).toEqual({
            valid: false,
            accountId: '',
            arn: '',
        });

        expect(mockSTS.getCallerIdentity).toHaveBeenCalledTimes(2);
        expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 5000);

        (global.setTimeout as jest.MockedFunction<typeof setTimeout>).mockRestore();
    });

    test('should succeed on retry after SignatureDoesNotMatch error', async () => {
        const error = new Error('The request signature we calculated does not match the signature you provided.');
        error.name = 'SignatureDoesNotMatch';

        const mockResponse = {
            Account: '123456789012',
            Arn: 'arn:aws:iam::123456789012:user/testuser',
            UserId: 'ACCESS_KEY',
        };

        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
            callback();
            return {} as NodeJS.Timeout;
        });

        mockSTS.getCallerIdentity
            .mockRejectedValueOnce(error)
            .mockResolvedValueOnce(mockResponse);

        const result = await validateAWSCredentials('ACCESS_KEY', 'SECRET_KEY');

        expect(result).toEqual({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/testuser',
        });

        expect(mockSTS.getCallerIdentity).toHaveBeenCalledTimes(2);
        expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 5000);

        (global.setTimeout as jest.MockedFunction<typeof setTimeout>).mockRestore();
    });

    test('should return invalid for other AWS errors', async () => {
        const error = new Error('Some other AWS error');
        error.name = 'AccessDenied';

        mockSTS.getCallerIdentity.mockRejectedValue(error);

        const result = await validateAWSCredentials('ACCESS_KEY', 'SECRET_KEY');

        expect(result).toEqual({
            valid: false,
            accountId: '',
            arn: '',
        });
    });

    test('should handle STS constructor errors and return error message', async () => {
        const error = new Error('STS constructor error');

        MockedSTS.mockImplementation(() => {
            throw error;
        });

        const result = await validateAWSCredentials('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

        expect(result).toEqual({
            valid: false,
            error: 'STS constructor error',
        });

        expect(console.error).toHaveBeenCalledWith('Error validating AWS credentials:', error);
    });

    test('should handle non-Error objects thrown during STS construction', async () => {
        const errorString = 'STS construction string error';

        MockedSTS.mockImplementation(() => {
            throw errorString;
        });

        const result = await validateAWSCredentials('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

        expect(result).toEqual({
            valid: false,
            error: 'STS construction string error',
        });

        expect(console.error).toHaveBeenCalledWith('Error validating AWS credentials:', errorString);
      });

    test('should not retry SignatureDoesNotMatch when retryOn403 is false', async () => {
        const error = new Error('The request signature we calculated does not match the signature you provided.');
        error.name = 'SignatureDoesNotMatch';
        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
            callback();
            return {} as NodeJS.Timeout;
        });

        mockSTS.getCallerIdentity.mockRejectedValue(error);

        const result = await validateAWSCredentials('AKIAIOSFODNN7EXAMPLE', 'WRONG_SECRET');
        expect(mockSTS.getCallerIdentity).toHaveBeenCalledTimes(2);

        expect(result).toEqual({
            valid: false,
            accountId: '',
            arn: '',
        });

        (global.setTimeout as jest.MockedFunction<typeof setTimeout>).mockRestore();
      });
});