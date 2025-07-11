import { deepseekConfig } from '../../../config/detectors/deepseek/deepseek';

export interface DeepSeekValidationResponse {
    is_available: boolean;
}

export interface DeepSeekValidationResult {
    valid: boolean;
    error?: string;
    response?: DeepSeekValidationResponse;
}

export async function validateDeepSeekApiKey(apiKey: string): Promise<DeepSeekValidationResult> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), deepseekConfig.api.timeout);

        const response = await fetch(`${deepseekConfig.api.baseUrl}${deepseekConfig.api.endpoints.balance}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Authorization': `Bearer ${apiKey}`
            },
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 200) {
            const data: DeepSeekValidationResponse = await response.json();
            return {
                valid: true,
                response: data
            };
        } else if (response.status === 401) {
            return {
                valid: false,
                error: 'Invalid API key'
            };
        } else {
            return {
                valid: false,
                error: `Unexpected status code: ${response.status}`
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