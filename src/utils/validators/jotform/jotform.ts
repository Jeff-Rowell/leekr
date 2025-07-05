import { JotFormValidationResult } from '../../../types/jotform';

export async function validateJotFormCredentials(apiKey: string): Promise<JotFormValidationResult> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        const response = await fetch(`https://api.jotform.com/user?apiKey=${apiKey}`, {
            method: 'GET',
            signal: controller.signal,
            headers: {
                'Accept': 'application/json',
                'User-Agent': 'Leekr-Security-Scanner/1.0'
            }
        });

        clearTimeout(timeoutId);

        if (response.status >= 200 && response.status < 300) {
            return {
                valid: true,
                error: ''
            };
        } else if (response.status === 401 || response.status === 403) {
            return {
                valid: false,
                error: 'Invalid API key'
            };
        } else {
            return {
                valid: false,
                error: `API returned status ${response.status}`
            };
        }
    } catch (error) {
        if (error instanceof Error) {
            if (error.name === 'AbortError') {
                return {
                    valid: false,
                    error: 'Request timeout'
                };
            }
            return {
                valid: false,
                error: error.message
            };
        }
        return {
            valid: false,
            error: 'Unknown error occurred'
        };
    }
}