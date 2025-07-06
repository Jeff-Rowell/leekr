export interface GroqValidationResult {
    valid: boolean;
    error: string | null;
}

export interface GroqOccurrence {
    secretType: string;
    fingerprint: string;
    secretValue: {
        match: {
            apiKey: string;
        };
    };
    filePath: string;
    url: string;
    type: string;
    sourceContent: {
        content: string;
        contentFilename: string;
        contentStartLineNum: number;
        contentEndLineNum: number;
        exactMatchNumbers: number[];
    };
    validity: string;
}

export interface GroqDetectorConfig {
    requiredEntropy: number;
}