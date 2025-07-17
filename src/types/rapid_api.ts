import { Occurrence } from './findings.types';

export interface RapidApiSecretValue {
    match: {
        api_key: string;
    };
}

export interface RapidApiOccurrence extends Occurrence {
    secretValue: RapidApiSecretValue;
    type: string;
    validity?: string;
}