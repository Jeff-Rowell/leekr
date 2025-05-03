
export interface Pattern {
    name: string;
    isValidityCustomizable: boolean;
    hasCustomValidity: boolean;
    validityEndpoints: string[];
    pattern: string;
    entropy: number;
}
