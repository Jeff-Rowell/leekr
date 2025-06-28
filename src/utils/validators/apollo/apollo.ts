import { ApolloValidationResult } from '../../../types/apollo';

export async function validateApolloCredentials(
    apiKey: string
): Promise<ApolloValidationResult> {
    try {
        const endpoint = 'https://api.apollo.io/v1/auth/health';

        const response = await fetch(endpoint, {
            method: 'GET',
            headers: {
                'x-api-key': apiKey
            }
        });
        
        // Check status code first
        if (response.status === 200) {
            // Only parse JSON for 200 OK responses
            const responseData = await response.json();

            // Check the is_logged_in field in the JSON response
            if (responseData && responseData.is_logged_in === true) {
                return {
                    valid: true,
                    error: ''
                };
            } else {
                return {
                    valid: false,
                    error: 'Apollo API key validation failed'
                };
            }
        } else if (response.status === 304) {
            return {
                valid: false,
                error: 'Invalid Apollo API key'
            };
        } else {
            return {
                valid: false,
                error: `HTTP ${response.status}: ${response.statusText}`
            };
        }
    } catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : 'Unknown validation error'
        };
    }
}