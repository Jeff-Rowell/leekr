export const AWS_RESOURCE_TYPES: Record<string, string> = {
    'ASIA': 'Temporary (AWS STS) access key IDs use this prefix, but are unique only in combination with the secret access key and the session token',
};

export const DEFAULT_AWS_SESSION_KEY_CONFIG = {
    requiredIdEntropy: 3.0,
    requiredSecretEntropy: 4.5
};
