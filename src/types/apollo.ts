import { ValidityStatus, Occurrence, SourceContent } from './findings.types';

export interface ApolloValidationResult {
    valid: boolean;
    error: string;
}

export interface ApolloSecretValue {
    match: {
        api_key: string;
    };
}

export interface ApolloOccurrence extends Occurrence {
    secretType: "Apollo";
    secretValue: ApolloSecretValue;
    type: string;
    sourceContent: SourceContent;
    validity?: ValidityStatus;
    validatedAt?: number;
}