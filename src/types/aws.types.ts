import { Occurrence } from './findings.types';

export interface AWSSecretValue {
    match: {
        access_key_id: string;
        secret_key_id: string;
    };
}

export interface AWSOccurrence extends Occurrence {
    secretValue: AWSSecretValue;
    resourceType?: string;
    accountId?: string;
    arn?: string;
    validity?: string;
}

export interface AWSDetectorConfig {
    requiredIdEntropy: number;
    requiredSecretEntropy: number;
}
