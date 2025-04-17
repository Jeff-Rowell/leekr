export type ValidityStatus = 'valid' | 'invalid' | 'failed_to_check' | 'no_checker' | 'unknown';

export interface Finding {
    secretType: string;
    filePath: string;
    validity: ValidityStatus;
    validatedAt?: string;
    secretValue: object;
    fingerprint: string;
    url: string;
}
