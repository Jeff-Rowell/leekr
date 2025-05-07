import { PatternsObj } from '../../types/patterns.types';
import { DEFAULT_AWS_CONFIG } from '../config/aws';
import { AWSDetectorConfig } from '../../types/aws.types';
import { storePatterns } from '../utils/common';

const awsConfig: AWSDetectorConfig = { ...DEFAULT_AWS_CONFIG };
export const patterns: PatternsObj = {
    "AWS Access Key": {
        name: "AWS Access Key",
        pattern: /\b((?:AKIA|ABIA|ACCA|AIDA)[A-Z0-9]{16})\b/g,
        entropy: awsConfig.requiredIdEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "AWS Secret Key": {
        name: "AWS Secret Key",
        pattern: /"([A-Za-z0-9+/]{40})"|(?:[^A-Za-z0-9+/]|^)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)/g,
        entropy: awsConfig.requiredSecretEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    }
}

storePatterns(patterns);