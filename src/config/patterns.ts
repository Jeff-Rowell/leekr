import { AWSDetectorConfig } from '../types/aws.types';
import { PatternsObj } from '../types/patterns.types';
import { storePatterns } from '../utils/helpers/common';
import { DEFAULT_AWS_ACCESS_KEY_CONFIG } from './detectors/aws/aws_access_keys/aws';
import { DEFAULT_AWS_SESSION_KEY_CONFIG } from './detectors/aws/aws_session_keys/session_keys';

const awsAccessKeyConfig: AWSDetectorConfig = { ...DEFAULT_AWS_ACCESS_KEY_CONFIG };
const awsSessionKeyConfig: AWSDetectorConfig = { ...DEFAULT_AWS_SESSION_KEY_CONFIG };
export const patterns: PatternsObj = {
    "AWS Access Key": {
        name: "AWS Access Key",
        familyName: "AWS Access & Secret Keys",
        pattern: /\b((?:AKIA|ABIA|ACCA|AIDA)[A-Z0-9]{16})\b/g,
        entropy: awsAccessKeyConfig.requiredIdEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "AWS Secret Key": {
        name: "AWS Secret Key",
        familyName: "AWS Access & Secret Keys",
        pattern: /"([A-Za-z0-9+/]{40})"|(?:[^A-Za-z0-9+/]|^)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)/g,
        entropy: awsAccessKeyConfig.requiredSecretEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "AWS Session Key ID": {
        name: "AWS Session Key",
        familyName: "AWS Session Keys",
        pattern: /\b((?:ASIA)[A-Z0-9]{16})\b/g,
        entropy: awsSessionKeyConfig.requiredIdEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "AWS Session Key": {
        name: "AWS Session Key",
        familyName: "AWS Session Keys",
        pattern: /(?:[^A-Za-z0-9+/]|\A)([a-zA-Z0-9+/]{100,}={0,3})(?:[^A-Za-z0-9+/=]|$)/g,
        entropy: awsSessionKeyConfig.requiredSecretEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    }
}

storePatterns(patterns);