import { Occurrence } from './findings.types';

export interface OpenAISecretValue {
    match: {
        api_key: string;
    };
}

export interface OpenAIOccurrence extends Occurrence {
    secretValue: OpenAISecretValue;
    type: string;
    validity?: string;
}

export interface OpenAIValidationResult {
    valid: boolean;
    type: string;
    error: string;
    id?: string;
    totalOrgs?: number;
    mfaEnabled?: boolean;
    createdAt?: string;
    description?: string;
    isPersonal?: boolean;
    isDefault?: boolean;
}