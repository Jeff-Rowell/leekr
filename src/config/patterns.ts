import { AWSDetectorConfig } from '../types/aws.types';
import { PatternsObj } from '../types/patterns.types';
import { storePatterns } from '../utils/helpers/common';
import { DEFAULT_AWS_ACCESS_KEY_CONFIG } from './detectors/aws/aws_access_keys/aws';
import { DEFAULT_AWS_SESSION_KEY_CONFIG } from './detectors/aws/aws_session_keys/aws';
import { DEFAULT_ANTHROPIC_API_KEY_CONFIG } from './detectors/anthropic/anthropic';
import { DEFAULT_OPENAI_API_KEY_CONFIG } from './detectors/openai/openai';
import { DEFAULT_GEMINI_API_KEY_CONFIG } from './detectors/gemini/gemini';

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
    },
    "Anthropic API Key": {
        name: "Anthropic API Key",
        familyName: "Anthropic AI",
        pattern: /\b(sk-ant-(?:admin01|api03)-[\w\-]{93}AA)\b/g,
        entropy: DEFAULT_ANTHROPIC_API_KEY_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "OpenAI API Key": {
        name: "OpenAI API Key",
        familyName: "OpenAI",
        pattern: /\b(sk-[a-zA-Z0-9_-]+T3BlbkFJ[a-zA-Z0-9_-]+)\b/g,
        entropy: DEFAULT_OPENAI_API_KEY_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Gemini API Key": {
        name: "Gemini API Key",
        familyName: "Gemini",
        pattern: /\b((?:master-|account-)[0-9A-Za-z]{20})\b/g,
        entropy: DEFAULT_GEMINI_API_KEY_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Gemini API Secret": {
        name: "Gemini API Secret",
        familyName: "Gemini",
        pattern: /\b([A-Za-z0-9]{27,28})\b/g,
        entropy: DEFAULT_GEMINI_API_KEY_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    }
}

storePatterns(patterns);