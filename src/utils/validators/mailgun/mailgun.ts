import { MailgunValidationResult, MailgunDomainResponse } from '../../../types/mailgun';

export async function validateMailgunCredentials(apiKey: string): Promise<MailgunValidationResult> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        let authHeader: string;
        if (apiKey.length === 72) {
            authHeader = `Basic ${apiKey}`;
        } else {
            const credentials = btoa(`api:${apiKey}`);
            authHeader = `Basic ${credentials}`;
        }

        const response = await fetch('https://api.mailgun.net/v3/domains', {
            method: 'GET',
            signal: controller.signal,
            credentials: 'omit',
            mode: 'cors',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (compatible; KeyValidator/1.0)',
                'Authorization': authHeader
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