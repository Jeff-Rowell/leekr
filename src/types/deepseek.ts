import { Occurrence } from './findings.types';

export interface DeepSeekOccurrence extends Occurrence {
    type: string;
    secretType: "DeepSeek";
    secretValue: {
        match: {
            apiKey: string;
        };
    };
}

export interface DeepSeekSecretValue {
    match: {
        apiKey: string;
    };
    validatedAt?: string;
    validity?: string;
}