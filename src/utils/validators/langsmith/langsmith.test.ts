import { validateLangsmithCredentials } from './langsmith';

global.fetch = jest.fn();

describe('validateLangsmithCredentials', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return valid for personal token with 200 response', async () => {
        (global.fetch as jest.Mock).mockResolvedValueOnce({
            status: 200,
        });

        const result = await validateLangsmithCredentials('lsv2_pt_12345678901234567890123456789012_1234567890');

        expect(result).toEqual({
            valid: true,
            type: 'personal',
            error: ''
        });
        expect(global.fetch).toHaveBeenCalledWith(
            'https://api.smith.langchain.com/api/v1/api-key',
            {
                method: 'GET',
                headers: {
                    'X-API-Key': 'lsv2_pt_12345678901234567890123456789012_1234567890',
                    'Content-Type': 'application/json',
                },
            }
        );
    });

    it('should return valid for service key with 200 response', async () => {
        (global.fetch as jest.Mock).mockResolvedValueOnce({
            status: 200,
        });

        const result = await validateLangsmithCredentials('lsv2_sk_abcdef01234567890123456789012345_abcdef0123');

        expect(result).toEqual({
            valid: true,
            type: 'service',
            error: ''
        });
    });

    it('should return invalid for 401 response', async () => {
        (global.fetch as jest.Mock).mockResolvedValueOnce({
            status: 401,
        });

        const result = await validateLangsmithCredentials('lsv2_pt_12345678901234567890123456789012_1234567890');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unauthorized'
        });
    });

    it('should return invalid for 403 response', async () => {
        (global.fetch as jest.Mock).mockResolvedValueOnce({
            status: 403,
        });

        const result = await validateLangsmithCredentials('lsv2_pt_12345678901234567890123456789012_1234567890');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unauthorized'
        });
    });

    it('should return error for unexpected status code', async () => {
        (global.fetch as jest.Mock).mockResolvedValueOnce({
            status: 500,
        });

        const result = await validateLangsmithCredentials('lsv2_pt_12345678901234567890123456789012_1234567890');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unexpected HTTP status 500'
        });
    });

    it('should return error when fetch throws AbortError', async () => {
        const abortError = new DOMException('Request was aborted', 'AbortError');
        (global.fetch as jest.Mock).mockRejectedValueOnce(abortError);

        const result = await validateLangsmithCredentials('lsv2_pt_12345678901234567890123456789012_1234567890');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Request was aborted'
        });
    });

    it('should return error when fetch throws other error', async () => {
        const networkError = new Error('Network error');
        (global.fetch as jest.Mock).mockRejectedValueOnce(networkError);

        const result = await validateLangsmithCredentials('lsv2_pt_12345678901234567890123456789012_1234567890');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: networkError
        });
    });
});