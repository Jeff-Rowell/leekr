import { ValidityStatus, Occurrence, SourceContent } from './findings.types';

export interface ArtifactoryValidationResult {
    valid: boolean;
    error: string;
    url?: string;
    tokenInfo?: string;
    permissions?: string[];
}

export interface ArtifactorySecretValue {
    match: {
        api_key: string;
        url?: string;
    };
}

export interface ArtifactoryOccurrence extends Occurrence {
    secretType: "Artifactory";
    secretValue: ArtifactorySecretValue;
    type: string;
    sourceContent: SourceContent;
    validity?: ValidityStatus;
    validatedAt?: number;
}