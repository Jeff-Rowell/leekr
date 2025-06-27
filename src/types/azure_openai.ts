import { ValidityStatus, Occurrence, SourceContent } from './findings.types';

export interface AzureOpenAIValidationResult {
    valid: boolean;
    error: string;
    url?: string;
    deployments?: string[];
    region?: string;
}

export interface AzureOpenAISecretValue {
    match: {
        api_key: string;
        url?: string;
    };
}

export interface AzureOpenAIOccurrence extends Occurrence {
    secretType: "Azure OpenAI";
    secretValue: AzureOpenAISecretValue;
    type: string;
    sourceContent: SourceContent;
    validity?: ValidityStatus;
    validatedAt?: number;
}