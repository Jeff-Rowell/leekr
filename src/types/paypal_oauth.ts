import { Occurrence } from './findings.types';

export interface PayPalOAuthSecretValue {
    match: {
        client_id: string;
        client_secret: string;
    };
}

export interface PayPalOAuthOccurrence extends Occurrence {
    secretValue: PayPalOAuthSecretValue;
    validity?: string;
}

export interface PayPalOAuthDetectorConfig {
    requiredClientIdEntropy: number;
    requiredClientSecretEntropy: number;
}

export interface PayPalTokenResponse {
    scope: string;
    access_token: string;
    token_type: string;
    app_id: string;
    expires_in: number;
    nonce: string;
}

export interface PayPalErrorResponse {
    error: string;
    error_description: string;
}

export interface PayPalValidationResult {
    valid: boolean;
    error?: string;
}