import { Occurrence } from './findings.types';

export interface HuggingFaceSecretValue {
    match: {
        api_key: string;
    };
}

export interface HuggingFaceOccurrence extends Occurrence {
    type: string;
    secretType: 'Hugging Face';
    secretValue: HuggingFaceSecretValue;
}

export interface HuggingFaceValidationResult {
    valid: boolean;
    type: 'USER' | 'ORGANIZATION' | 'unknown';
    error: string;
    username?: string;
    email?: string;
    tokenInfo?: string;
    organizations?: string[];
}

export interface HuggingFaceOrganization {
    name: string;
    roleInOrg: string;
}

export interface HuggingFaceAuth {
    accessToken?: {
        displayName?: string;
        role?: string;
    };
    type?: string;
}

export interface HuggingFaceWhoamiResponse {
    name: string;
    email: string;
    orgs: HuggingFaceOrganization[];
    auth: HuggingFaceAuth;
}