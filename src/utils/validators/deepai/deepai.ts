import { deepaiConfig } from '../../../config/detectors/deepai/deepai';

export interface DeepAIValidationResponse {
    id: string;
    output?: any;
}

export interface DeepAIValidationResult {
    valid: boolean;
    error?: string;
    response?: DeepAIValidationResponse;
}

export async function validateDeepAIApiKey(apiKey: string): Promise<DeepAIValidationResult> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), deepaiConfig.api.timeout);

        const formData = new FormData();
        formData.append('text', 'test');

        const response = await fetch(`${deepaiConfig.api.baseUrl}${deepaiConfig.api.endpoints.textTagging}`, {
            method: 'POST',
            headers: {
                'api-key': apiKey
            },
            body: formData,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status >= 200 && response.status < 300) {
            const data: DeepAIValidationResponse = await response.json();
            return {
                valid: true,
                response: data
            };
        } else if (response.status === 401 || response.status === 403) {
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