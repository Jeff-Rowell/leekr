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