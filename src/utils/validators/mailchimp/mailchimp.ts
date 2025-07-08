import { MailchimpValidationResult, MailchimpResponse } from '../../../types/mailchimp';

export async function validateMailchimpCredentials(apiKey: string): Promise<MailchimpValidationResult> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        const datacenter = apiKey.split('-')[1];
        if (!datacenter) {
            return {
                valid: false,
                error: 'Invalid API key format - missing datacenter'
            };
        }

        const credentials = btoa(`anystring:${apiKey}`);

        const response = await fetch(`https://${datacenter}.api.mailchimp.com/3.0/`, {
            method: 'GET',
            signal: controller.signal,
            credentials: 'omit',
            mode: 'cors',
            headers: {
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Authorization': `Basic ${credentials}`
            }
        });
        clearTimeout(timeoutId);

        if (response.status >= 200 && response.status < 300) {
            return {
                valid: true,
                error: null
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