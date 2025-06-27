import { AzureOpenAIValidationResult } from '../../../types/azure_openai';

export async function validateAzureOpenAICredentials(
    apiKey: string, 
    url?: string
): Promise<AzureOpenAIValidationResult> {
    try {
        let azureUrl = url;
        if (!azureUrl) {
            return {
                valid: false,
                error: 'Azure OpenAI URL is required for validation'
            };
        }

        if (!azureUrl.startsWith('http://') && !azureUrl.startsWith('https://')) {
            azureUrl = 'https://' + azureUrl;
        }

        const endpoint = `${azureUrl}/openai/models?api-version=2024-02-01`;

        const response = await fetch(endpoint, {
            method: 'GET',
            headers: {
                'Api-Key': apiKey,
                'Content-Type': 'application/json'
            }
        });

        if (response.ok) {
            const data = await response.json();
            
            if (data && (data.object === "list" || data.data)) {
                const urlMatch = azureUrl.match(/https?:\/\/([^.]+)\.openai\.azure\.com/);
                const region = urlMatch ? urlMatch[1] : 'unknown';
                
                return {
                    valid: true,
                    error: '',
                    url: azureUrl,
                    deployments: data.data ? data.data.map((d: any) => d.id) : [],
                    region: region
                };
            } else {
                return {
                    valid: false,
                    error: 'Invalid response structure from Azure OpenAI API',
                    url: azureUrl
                };
            }
        } else if (response.status === 403) {
            return {
                valid: false,
                error: 'API key exists but lacks required permissions',
                url: azureUrl
            };
        } else if (response.status === 401) {
            return {
                valid: false,
                error: 'Invalid Azure OpenAI API key',
                url: azureUrl
            };
        } else if (response.status === 404) {
            return {
                valid: false,
                error: 'Azure OpenAI service not found at this URL',
                url: azureUrl
            };
        } else {
            return {
                valid: false,
                error: `HTTP ${response.status}: ${response.statusText}`,
                url: azureUrl
            };
        }
    } catch (error) {
        if (error instanceof Error && error.message.includes('no such host')) {
            return {
                valid: false,
                error: 'Azure OpenAI service URL does not exist'
            };
        }
        
        return {
            valid: false,
            error: error instanceof Error ? error.message : 'Unknown validation error'
        };
    }
}