export interface MailgunValidationResult {
    valid: boolean;
    error: string | null;
}

export interface MailgunOccurrence {
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

export interface MailgunDetectorConfig {
    requiredEntropy: number;
}

export interface MailgunDomainResponse {
    total_count: number;
    items: MailgunDomain[];
}

export interface MailgunDomain {
    id: string;
    is_disabled: boolean;
    name: string;
    state: string;
    type: string;
}