export const AWS_RESOURCE_TYPES: Record<string, string> = {
    'AKIA': 'Access Key',
    'ABIA': 'AWS STS Service Bearer Token',
    'ACCA': 'Context-specific Credential'
};

export const DEFAULT_AWS_ACCESS_KEY_CONFIG = {
    requiredIdEntropy: 3.0,
    requiredSecretEntropy: 4.25
};
