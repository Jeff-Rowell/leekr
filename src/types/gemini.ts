import { Occurrence } from './findings.types';

export interface GeminiSecretValue {
    match: {
        api_key: string;
        api_secret: string;
    };
}

export interface GeminiOccurrence extends Occurrence {
    secretValue: GeminiSecretValue;
    type: string;
    validity?: string;
}

export interface GeminiValidationResult {
    valid: boolean;
    type: string;
    error: string;
    account?: string;
    name?: string;
    isMainAccount?: boolean;
    isActive?: boolean;
    tradeVolume?: number;
    accountCreated?: string;
}