import { validateRapidApiCredentials } from './rapid_api';

global.fetch = jest.fn();

describe('validateRapidApiCredentials', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return valid when API responds with 200', async () => {
        (fetch as jest.Mock).mockResolvedValue({
            status: 200,
        });

        const result = await validateRapidApiCredentials('validApiKey12345678901234567890123456789012345678');

        expect(result).toEqual({
            valid: true,
            type: 'API_KEY',
            error: null
        });

        expect(fetch).toHaveBeenCalledWith(
            'https://covid-193.p.rapidapi.com/countries',
            {
                method: 'GET',
                headers: {
                    'x-rapidapi-key': 'validApiKey12345678901234567890123456789012345678',
                    "x-rapidapi-host": "covid-193.p.rapidapi.com",
                    'Content-Type': 'application/json',
                },
            }
        );
    });

    it('should return valid when API responds with 201', async () => {
        (fetch as jest.Mock).mockResolvedValue({
            status: 201,
        });

        const result = await validateRapidApiCredentials('validApiKey12345678901234567890123456789012345678');

        expect(result).toEqual({
            valid: true,
            type: 'API_KEY',
            error: null
        });
    });

    it('should return valid when API responds with 299', async () => {
        (fetch as jest.Mock).mockResolvedValue({
            status: 299,
        });

        const result = await validateRapidApiCredentials('validApiKey12345678901234567890123456789012345678');

        expect(result).toEqual({
            valid: true,
            type: 'API_KEY',
            error: null
        });
    });

    it('should return invalid when API responds with 401', async () => {
        (fetch as jest.Mock).mockResolvedValue({
            status: 401,
        });

        const result = await validateRapidApiCredentials('invalidApiKey12345678901234567890123456789012345678');

        expect(result).toEqual({
            valid: false,
            type: 'API_KEY',
            error: 'Unauthorized'
        });
    });

    it('should return invalid when API responds with 403', async () => {
        (fetch as jest.Mock).mockResolvedValue({
            status: 403,
        });

        const result = await validateRapidApiCredentials('forbiddenApiKey1234567890123456789012345678901234');

        expect(result).toEqual({
            valid: false,
            type: 'API_KEY',
            error: 'Unauthorized'
        });
    });

    it('should return invalid when API responds with unexpected status', async () => {
        (fetch as jest.Mock).mockResolvedValue({
            status: 500,
        });

        const result = await validateRapidApiCredentials('errorApiKey12345678901234567890123456789012345678901');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Unexpected HTTP status 500 from https://covid-193.p.rapidapi.com/countries'
        });
    });

    it('should return invalid when request is aborted', async () => {
        const abortError = new DOMException('Request was aborted', 'AbortError');
        (fetch as jest.Mock).mockRejectedValue(abortError);

        const result = await validateRapidApiCredentials('abortedApiKey123456789012345678901234567890123456789');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: 'Request was aborted'
        });
    });

    it('should return invalid when fetch throws non-abort error', async () => {
        const networkError = new Error('Network error');
        (fetch as jest.Mock).mockRejectedValue(networkError);

        const result = await validateRapidApiCredentials('networkErrorApiKey12345678901234567890123456789012');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: networkError
        });
    });

    it('should return invalid when fetch throws generic error', async () => {
        const genericError = 'Some string error';
        (fetch as jest.Mock).mockRejectedValue(genericError);

        const result = await validateRapidApiCredentials('genericErrorApiKey1234567890123456789012345678901');

        expect(result).toEqual({
            valid: false,
            type: 'unknown',
            error: genericError
        });
    });
});