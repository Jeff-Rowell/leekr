import { Occurrence } from './findings.types';

export interface MakeSecretValue {
    match: {
        api_token: string;
    };
}

export interface MakeOccurrence extends Occurrence {
    secretValue: MakeSecretValue;
    validity?: string;
}

export interface MakeDetectorConfig {
    requiredEntropy: number;
}

export interface MakeValidationResponse {
    valid: boolean;
    error?: string;
}