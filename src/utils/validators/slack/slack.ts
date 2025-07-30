interface SlackAuthResponse {
    ok: boolean;
    url?: string;
    team?: string;
    user?: string;
    team_id?: string;
    user_id?: string;
    bot_id?: string;
    error?: string;
}

export async function validateSlackToken(token: string): Promise<{
    valid: boolean;
    url?: string;
    team?: string;
    user?: string;
    teamId?: string;
    userId?: string;
    botId?: string;
    error?: string;
}> {
    try {
        const response = await fetch('https://slack.com/api/auth.test', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            return {
                valid: false,
                error: `HTTP ${response.status}: ${response.statusText}`
            };
        }

        const authResponse: SlackAuthResponse = await response.json();

        if (authResponse.ok) {
            return {
                valid: true,
                url: authResponse.url,
                team: authResponse.team,
                user: authResponse.user,
                teamId: authResponse.team_id,
                userId: authResponse.user_id,
                botId: authResponse.bot_id
            };
        } else if (authResponse.error === 'invalid_auth') {
            return {
                valid: false,
                error: 'Invalid authentication token'
            };
        } else if (authResponse.error === 'account_inactive') {
            return {
                valid: false,
                error: 'Authentication token is for a deleted user or workspace'
            };
        } else if (authResponse.error === 'token_revoked') {
            return {
                valid: false,
                error: 'Authentication token has been revoked'
            };
        } else {
            return {
                valid: false,
                error: authResponse.error || 'Unknown error'
            };
        }
    } catch (error) {
        console.error('Error validating Slack token:', error);
        return {
            valid: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}