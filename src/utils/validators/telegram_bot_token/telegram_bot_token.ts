const BOT_TOKEN_ENDPOINT = "https://api.telegram.org/bot";

export async function validateTelegramBotTokenCredentials(botToken: string): Promise<{ valid: boolean; type: string; error: any; username?: string }> {
    try {
        const res = await fetch(`${BOT_TOKEN_ENDPOINT}${botToken}/getMe`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (res.status >= 200 && res.status < 300) {
            const data = await res.json();
            if (data.ok) {
                return { 
                    valid: true, 
                    type: 'BOT_TOKEN', 
                    error: null,
                    username: data.result.username
                };
            } else {
                return { 
                    valid: false, 
                    type: 'BOT_TOKEN', 
                    error: data.description || 'Invalid bot token'
                };
            }
        }

        if (res.status === 401 || res.status === 404) {
            return { 
                valid: false, 
                type: 'BOT_TOKEN', 
                error: 'Unauthorized or not found'
            };
        }

        return {
            valid: false,
            type: 'BOT_TOKEN',
            error: `Unexpected HTTP status ${res.status}`,
        };
    } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') {
            return { valid: false, type: 'BOT_TOKEN', error: 'Request was aborted' };
        }
        return { valid: false, type: 'BOT_TOKEN', error: err };
    }
}