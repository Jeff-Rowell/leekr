export type ValidityStatus = 'valid' | 'invalid' | 'failed_to_check' | 'no_checker' | 'unknown';
export type DetectorType = 'AWS Access & Secret Keys' | 'AWS Session Keys';

export interface Occurrence {
    secretType: DetectorType;
    fingerprint: string;
    secretValue: object;
    filePath: string;
    url: string;
}

export interface Finding {
    numOccurrences: number;
    secretType: DetectorType;
    secretValue: object;
    validity: ValidityStatus;
    validatedAt?: string;
    fingerprint: string;
    occurrences: Set<Occurrence>;
}

export interface FindingDict {
    // fingerprint as the key, all matching occurrences as the values
    [key: string]: Set<Occurrence>;
}

export type NullableFinding = Finding | null;
export type NullableOccurrence = Occurrence | null;
