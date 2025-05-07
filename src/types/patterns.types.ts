
export interface Pattern {
    name: string;
    isValidityCustomizable: boolean;
    hasCustomValidity: boolean;
    validityEndpoints: string[];
    pattern: RegExp;
    entropy: number;
    global: boolean;
}

export interface PatternsObj {
    [key: string]: Pattern
}