import { Occurrence } from './findings.types';

export interface LangsmithSecretValue {
    match: {
        api_key: string;
    };
}

export interface LangsmithOccurrence extends Occurrence {
    secretValue: LangsmithSecretValue;
    type: string;
    validity?: string;
}