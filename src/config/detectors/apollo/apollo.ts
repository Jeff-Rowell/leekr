export const APOLLO_RESOURCE_TYPES: Record<string, string> = {
    'API_KEY': 'API Key',
};

export const DEFAULT_APOLLO_API_KEY_CONFIG = {
    requiredEntropy: 3.9,
    // Patterns to detect false positives (programming naming conventions)
    falsePositivePatterns: [
        // PascalCase: starts with capital, followed by lowercase, then more capital+lowercase groups
        /^[A-Z][a-z]+([A-Z][a-z]+)+$/,
        // camelCase: starts with lowercase, then capital+lowercase groups
        /^[a-z]+([A-Z][a-z]+)+$/,
        // Mixed case with acronyms: 3+ consecutive capitals in the middle of the string
        /^[A-Za-z]*[A-Z]{3,}[A-Za-z]*$/,
        // Common programming patterns with obvious version numbers or IDs
        /^[A-Za-z]+\d{1,3}[A-Za-z]+$/
    ]
};