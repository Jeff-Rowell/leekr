export interface JotFormMatch {
    apiKey: string;
}

export interface JotFormOccurrence {
    secretType: string;
    fingerprint: string;
    secretValue: {
        match: JotFormMatch;
    };
    filePath: string;
    url: string;
    type: string;
    sourceContent: any;
    validity: string;
}

export interface JotFormDetectorConfig {
    requiredEntropy: number;
}

export interface JotFormValidationResult {
    valid: boolean;
    error: string;
}