import { Occurrence } from './findings.types';

export interface DeepAIOccurrence extends Occurrence {
    type: string;
    secretType: "DeepAI";
    secretValue: {
        match: {
            apiKey: string;
        };
    };
    validity?: string;
    validatedAt?: string;
}

export interface DeepAISecretValue {
    match: {
        apiKey: string;
    };
    validatedAt?: string;
    validity?: string;
}