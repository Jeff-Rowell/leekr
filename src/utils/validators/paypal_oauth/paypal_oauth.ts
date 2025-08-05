import { PayPalTokenResponse, PayPalErrorResponse, PayPalValidationResult } from '../../../types/paypal_oauth';

export async function validatePayPalOAuthCredentials(clientId: string, clientSecret: string): Promise<PayPalValidationResult> {
    try {
        const credentials = btoa(`${clientId}:${clientSecret}`);
        
        const response = await fetch('https://api-m.sandbox.paypal.com/v1/oauth2/token', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Accept-Language': 'en_US',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Basic ${credentials}`
            },
            body: 'grant_type=client_credentials'
        });

        if (response.status >= 200 && response.status < 300) {
            const data = await response.json() as PayPalTokenResponse;
            return {
                valid: true
            };
        } else {
            const errorData = await response.json() as PayPalErrorResponse;
            return {
                valid: false,
                error: errorData.error_description || errorData.error
            };
        }
    } catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : 'Unknown error occurred'
        };
    }
}