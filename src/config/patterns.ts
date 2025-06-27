import { AWSDetectorConfig } from '../types/aws.types';
import { PatternsObj } from '../types/patterns.types';
import { storePatterns } from '../utils/helpers/common';
import { DEFAULT_AWS_ACCESS_KEY_CONFIG } from './detectors/aws/aws_access_keys/aws';
import { DEFAULT_AWS_SESSION_KEY_CONFIG } from './detectors/aws/aws_session_keys/aws';
import { DEFAULT_ANTHROPIC_API_KEY_CONFIG } from './detectors/anthropic/anthropic';
import { DEFAULT_OPENAI_API_KEY_CONFIG } from './detectors/openai/openai';
import { DEFAULT_GEMINI_API_KEY_CONFIG } from './detectors/gemini/gemini';
import { DEFAULT_HUGGINGFACE_API_KEY_CONFIG } from './detectors/huggingface/huggingface';
import { DEFAULT_ARTIFACTORY_ACCESS_TOKEN_CONFIG, DEFAULT_ARTIFACTORY_URL_CONFIG } from './detectors/artifactory/artifactory';
import { DEFAULT_AZURE_OPENAI_API_KEY_CONFIG, DEFAULT_AZURE_OPENAI_URL_CONFIG } from './detectors/azure_openai/azure_openai';

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
    },
    "Hugging Face API Key": {
        name: "Hugging Face API Key",
        familyName: "Hugging Face",
        pattern: /\b((?:hf_|api_org_)[a-zA-Z0-9]{34})\b/g,
        entropy: DEFAULT_HUGGINGFACE_API_KEY_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Artifactory Access Token": {
        name: "Artifactory Access Token",
        familyName: "Artifactory",
        pattern: /\b([a-zA-Z0-9]{73}|[a-zA-Z0-9]{64})\b/g,
        entropy: DEFAULT_ARTIFACTORY_ACCESS_TOKEN_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Artifactory URL": {
        name: "Artifactory URL",
        familyName: "Artifactory",
        pattern: /\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])\.jfrog\.io)\b/g,
        entropy: DEFAULT_ARTIFACTORY_URL_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Azure OpenAI API Key": {
        name: "Azure OpenAI API Key",
        familyName: "Azure OpenAI",
        pattern: /\b([A-Za-z0-9]{84})\b/g,
        entropy: DEFAULT_AZURE_OPENAI_API_KEY_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Azure OpenAI URL": {
        name: "Azure OpenAI URL",
        familyName: "Azure OpenAI",
        pattern: /\b([a-z0-9-]+\.openai\.azure\.com)\b/g,
        entropy: DEFAULT_AZURE_OPENAI_URL_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    }
}

storePatterns(patterns);