import { Occurrence } from './findings.types';

export interface AnthropicSecretValue {
    match: {
        api_key: string;
    };
}

export interface AnthropicOccurrence extends Occurrence {
    secretValue: AnthropicSecretValue;
    type: string;
    validity?: string;
}