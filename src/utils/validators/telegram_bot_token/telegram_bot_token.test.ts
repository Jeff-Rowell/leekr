import { validateTelegramBotTokenCredentials } from './telegram_bot_token';

global.fetch = jest.fn();

describe('validateTelegramBotTokenCredentials', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return valid result when API responds with success', async () => {
        const mockResponse = {
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue({
                ok: true,
                result: {
                    username: 'testbot'
                }
            })
        };

        (fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateTelegramBotTokenCredentials('123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi');

        expect(result).toEqual({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        expect(fetch).toHaveBeenCalledWith(
            'https://api.telegram.org/bot123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi/getMe',
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
            }
        );
    });

    it('should return invalid result when API responds with error', async () => {
        const mockResponse = {
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue({
                ok: false,
                description: 'Unauthorized'
            })
        };

        (fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateTelegramBotTokenCredentials('invalid_token');

        expect(result).toEqual({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Unauthorized'
        });
    });

    it('should return invalid result when API responds with error without description', async () => {
        const mockResponse = {
            ok: true,
            status: 200,
            json: jest.fn().mockResolvedValue({
                ok: false
            })
        };

        (fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateTelegramBotTokenCredentials('invalid_token');

        expect(result).toEqual({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Invalid bot token'
        });
    });

    it('should return invalid result when API responds with 401 status', async () => {
        const mockResponse = {
            ok: false,
            status: 401,
            json: jest.fn()
        };

        (fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateTelegramBotTokenCredentials('invalid_token');

        expect(result).toEqual({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Unauthorized or not found'
        });
    });

    it('should return invalid result when API responds with 404 status', async () => {
        const mockResponse = {
            ok: false,
            status: 404,
            json: jest.fn()
        };

        (fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateTelegramBotTokenCredentials('invalid_token');

        expect(result).toEqual({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Unauthorized or not found'
        });
    });

    it('should return invalid result when API responds with unexpected status', async () => {
        const mockResponse = {
            ok: false,
            status: 500,
            json: jest.fn()
        };

        (fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateTelegramBotTokenCredentials('invalid_token');

        expect(result).toEqual({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Unexpected HTTP status 500'
        });
    });

    it('should handle AbortError', async () => {
        const abortError = new DOMException('Request was aborted', 'AbortError');
        (fetch as jest.Mock).mockRejectedValue(abortError);

        const result = await validateTelegramBotTokenCredentials('test_token');

        expect(result).toEqual({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Request was aborted'
        });
    });

    it('should handle generic network error', async () => {
        const networkError = new Error('Network error');
        (fetch as jest.Mock).mockRejectedValue(networkError);

        const result = await validateTelegramBotTokenCredentials('test_token');

        expect(result).toEqual({
            valid: false,
            type: 'BOT_TOKEN',
            error: networkError
        });
    });

    it('should handle JSON parsing error', async () => {
        const mockResponse = {
            ok: true,
            status: 200,
            json: jest.fn().mockRejectedValue(new Error('Invalid JSON'))
        };

        (fetch as jest.Mock).mockResolvedValue(mockResponse);

        const result = await validateTelegramBotTokenCredentials('test_token');

        expect(result).toEqual({
            valid: false,
            type: 'BOT_TOKEN',
            error: new Error('Invalid JSON')
        });
    });
});