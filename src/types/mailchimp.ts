export interface MailchimpValidationResult {
    valid: boolean;
    error: string | null;
}

export interface MailchimpOccurrence {
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

export interface MailchimpDetectorConfig {
    requiredEntropy: number;
}

export interface MailchimpResponse {
    account_id: string;
    account_name: string;
    email: string;
}