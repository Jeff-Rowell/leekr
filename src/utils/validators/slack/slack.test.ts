import { validateSlackToken } from './slack';

const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('validateSlackToken', () => {
    beforeEach(() => {
        mockFetch.mockClear();
    });

    it('should return valid true for successful auth', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: true,
                url: 'https://test-workspace.slack.com',
                team: 'Test Team',
                user: 'test-user',
                team_id: 'T1234567',
                user_id: 'U1234567',
                bot_id: 'B1234567'
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxb-1234567890-1234567890-test-token');

        expect(result).toEqual({
            valid: true,
            url: 'https://test-workspace.slack.com',
            team: 'Test Team',
            user: 'test-user',
            teamId: 'T1234567',
            userId: 'U1234567',
            botId: 'B1234567'
        });
        expect(mockFetch).toHaveBeenCalledWith('https://slack.com/api/auth.test', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Authorization': 'Bearer xoxb-1234567890-1234567890-test-token'
            }
        });
    });

    it('should return valid true without optional fields', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: true
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxp-1234567890-1234567890-test-token');

        expect(result).toEqual({
            valid: true,
            url: undefined,
            team: undefined,
            user: undefined,
            teamId: undefined,
            userId: undefined,
            botId: undefined
        });
    });

    it('should return valid false for invalid_auth error', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: false,
                error: 'invalid_auth'
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('invalid-token');

        expect(result).toEqual({
            valid: false,
            error: 'Invalid authentication token'
        });
    });

    it('should return valid false for account_inactive error', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: false,
                error: 'account_inactive'
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxb-1234567890-1234567890-inactive-token');

        expect(result).toEqual({
            valid: false,
            error: 'Authentication token is for a deleted user or workspace'
        });
    });

    it('should return valid false for token_revoked error', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: false,
                error: 'token_revoked'
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxb-1234567890-1234567890-revoked-token');

        expect(result).toEqual({
            valid: false,
            error: 'Authentication token has been revoked'
        });
    });

    it('should return valid false for unknown error', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: false,
                error: 'unknown_error'
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxb-1234567890-1234567890-error-token');

        expect(result).toEqual({
            valid: false,
            error: 'unknown_error'
        });
    });

    it('should return valid false for HTTP error', async () => {
        const mockResponse = {
            ok: false,
            status: 400,
            statusText: 'Bad Request'
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxb-1234567890-1234567890-bad-token');

        expect(result).toEqual({
            valid: false,
            error: 'HTTP 400: Bad Request'
        });
    });

    it('should handle fetch error', async () => {
        mockFetch.mockRejectedValue(new Error('Network error'));

        const result = await validateSlackToken('xoxb-1234567890-1234567890-network-error');

        expect(result).toEqual({
            valid: false,
            error: 'Network error'
        });
    });

    it('should handle non-Error exceptions', async () => {
        mockFetch.mockRejectedValue('String error');

        const result = await validateSlackToken('xoxb-1234567890-1234567890-string-error');

        expect(result).toEqual({
            valid: false,
            error: 'String error'
        });
    });

    it('should return "Unknown error" when authResponse.error is undefined', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: false
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxb-1234567890-1234567890-undefined-error');

        expect(result).toEqual({
            valid: false,
            error: 'Unknown error'
        });
    });

    it('should return "Unknown error" when authResponse.error is null', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: false,
                error: null
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxb-1234567890-1234567890-null-error');

        expect(result).toEqual({
            valid: false,
            error: 'Unknown error'
        });
    });

    it('should return "Unknown error" when authResponse.error is empty string', async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                ok: false,
                error: ''
            })
        };
        mockFetch.mockResolvedValue(mockResponse);

        const result = await validateSlackToken('xoxb-1234567890-1234567890-empty-error');

        expect(result).toEqual({
            valid: false,
            error: 'Unknown error'
        });
    });
});