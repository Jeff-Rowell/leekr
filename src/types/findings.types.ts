export type ValidityStatus = 'valid' | 'invalid' | 'failed_to_check' | 'no_checker' | 'unknown';

export interface Occurrence {
    secretType: string;
    fingerprint: string;
    secretValue: object;
    filePath: string;
    url: string;
}

export interface Finding {
    numOccurrences: number;
    secretType: string;
    secretValue: object;
    validity: ValidityStatus;
    validatedAt?: string;
    fingerprint: string;
    occurrences: Set<Occurrence>;
}

export type NullableFinding = Finding | null;
export type NullableOccurrence = Occurrence | null;
