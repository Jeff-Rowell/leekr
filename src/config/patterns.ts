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
import { DEFAULT_APOLLO_API_KEY_CONFIG } from './detectors/apollo/apollo';
import { DEFAULT_GCP_SERVICE_ACCOUNT_CONFIG } from './detectors/gcp/gcp';
import { DEFAULT_DOCKER_CONFIG } from './detectors/docker/docker';
import { DEFAULT_JOTFORM_CONFIG } from './detectors/jotform/jotform';
import { DEFAULT_GROQ_CONFIG } from './detectors/groq/groq';
import { DEFAULT_MAILGUN_CONFIG } from './detectors/mailgun/mailgun';
import { DEFAULT_MAILCHIMP_CONFIG } from './detectors/mailchimp/mailchimp';
import { deepseekConfig } from './detectors/deepseek/deepseek';
import { deepaiConfig } from './detectors/deepai/deepai';
import { DEFAULT_TELEGRAM_BOT_TOKEN_CONFIG } from './detectors/telegram_bot_token/telegram_bot_token';
import { DEFAULT_RAPID_API_CONFIG } from './detectors/rapid_api/rapid_api';
import { DEFAULT_MAKE_CONFIG } from './detectors/make/make';

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
    },
    "Apollo API Key": {
        name: "Apollo API Key",
        familyName: "Apollo",
        pattern: /\b([a-zA-Z0-9-_]{22})\b/g,
        entropy: DEFAULT_APOLLO_API_KEY_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Service Account Key": {
        name: "GCP Service Account Key",
        familyName: "Google Cloud Platform",
        pattern: /(?:service_account|private_key|auth_provider_x509_cert_url|gserviceaccount\.com)/g,
        entropy: DEFAULT_GCP_SERVICE_ACCOUNT_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Service Account Type": {
        name: "GCP Service Account Type",
        familyName: "Google Cloud Platform",
        pattern: /["']?service_account["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Project ID": {
        name: "GCP Project ID",
        familyName: "Google Cloud Platform",
        pattern: /["']([a-z][a-z0-9-]{4,28}[a-z0-9])["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Private Key ID": {
        name: "GCP Private Key ID",
        familyName: "Google Cloud Platform",
        pattern: /["']([a-f0-9]{40})["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Private Key": {
        name: "GCP Private Key",
        familyName: "Google Cloud Platform",
        pattern: /["']?(-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----)["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Client Email": {
        name: "GCP Client Email",
        familyName: "Google Cloud Platform",
        pattern: /["']?([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com)["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Client ID": {
        name: "GCP Client ID",
        familyName: "Google Cloud Platform",
        pattern: /["']?(\d{21})["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Auth Provider URL": {
        name: "GCP Auth Provider URL",
        familyName: "Google Cloud Platform",
        pattern: /["']?(https:\/\/www\.googleapis\.com\/oauth2\/v1\/certs)["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Project ID Context": {
        name: "GCP Project ID Context",
        familyName: "Google Cloud Platform",
        pattern: /(?:["']?project_id["']?\s*:\s*["']([a-z][a-z0-9-]{4,28}[a-z0-9])["']|(?:const|let|var)?\s*projectId\s*=\s*["']([a-z][a-z0-9-]{4,28}[a-z0-9])["'])/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Private Key ID Context": {
        name: "GCP Private Key ID Context",
        familyName: "Google Cloud Platform",
        pattern: /(?:["']?private_key_id["']?\s*:\s*["']([a-f0-9A-F\w]{4,})["']|(?:const|let|var)?\s*keyId\s*=\s*["']([a-f0-9A-F\w]{4,})["'])/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Private Key Context": {
        name: "GCP Private Key Context",
        familyName: "Google Cloud Platform",
        pattern: /(?:["']?private_key["']?\s*:\s*["']?(-----BEGIN PRIVATE KEY-----[\\s\\S]*?-----END PRIVATE KEY-----[\\s]*?)["']?|(?:const|let|var)?\s*privateKey\s*=\s*["']?(-----BEGIN PRIVATE KEY-----[\\s\\S]*?-----END PRIVATE KEY-----[\\s]*?)["']?)/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Client Email Context": {
        name: "GCP Client Email Context",
        familyName: "Google Cloud Platform",
        pattern: /(?:["']?client_email["']?\s*:\s*["']([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com)["']|(?:const|let|var)?\s*email\s*=\s*["']([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com)["'])/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Client ID Context": {
        name: "GCP Client ID Context",
        familyName: "Google Cloud Platform",
        pattern: /["']?client_id["']?\s*:\s*["'](\d{21})["']/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Auth Provider Context": {
        name: "GCP Auth Provider Context",
        familyName: "Google Cloud Platform",
        pattern: /(?:["']?auth_provider_x509_cert_url["']?\s*:\s*["'](https:\/\/www\.googleapis\.com\/oauth2\/v1\/certs)["']|(?:const|let|var)?\s*authUrl\s*=\s*["'](https:\/\/www\.googleapis\.com\/oauth2\/v1\/certs)["'])/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Auth URI": {
        name: "GCP Auth URI",
        familyName: "Google Cloud Platform",
        pattern: /["']?(https:\/\/accounts\.google\.com\/o\/oauth2\/auth)["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Token URI": {
        name: "GCP Token URI",
        familyName: "Google Cloud Platform",
        pattern: /["']?(https:\/\/oauth2\.googleapis\.com\/token)["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Client Cert URL": {
        name: "GCP Client Cert URL",
        familyName: "Google Cloud Platform",
        pattern: /["']?(https:\/\/www\.googleapis\.com\/robot\/v1\/metadata\/x509\/[^"']+)["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "GCP Universe Domain": {
        name: "GCP Universe Domain",
        familyName: "Google Cloud Platform",
        pattern: /["']?(googleapis\.com)["']?/g,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Docker Auth Config": {
        name: "Docker Auth Config",
        familyName: "Docker",
        pattern: /auths[\s\S]{1,1500}/gi,
        entropy: DEFAULT_DOCKER_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Docker Auths Structure": {
        name: "Docker Auths Structure",
        familyName: "Docker",
        pattern: /[\"']?auths[\"']?\s*:\s*\{/gi,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Docker Registry Pattern": {
        name: "Docker Registry Pattern", 
        familyName: "Docker",
        pattern: /[\"']([a-z0-9\-.:/]+(?:\.[a-z]{2,}|\.io|\.com|\.org)(?::\d+)?(?:\/[a-z0-9\-._/]*)?)[\"']\s*:\s*\{([^}]+)\}/gi,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Docker Auth Token Pattern": {
        name: "Docker Auth Token Pattern",
        familyName: "Docker", 
        pattern: /[\"']?auth[\"']?\s*:\s*[\"']([^\"']+)[\"']/gi,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Docker Username Pattern": {
        name: "Docker Username Pattern",
        familyName: "Docker",
        pattern: /[\"']?username[\"']?\s*:\s*[\"']([^\"']+)[\"']/gi,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Docker Password Pattern": {
        name: "Docker Password Pattern",
        familyName: "Docker",
        pattern: /[\"']?password[\"']?\s*:\s*[\"']([^\"']+)[\"']/gi,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Docker Email Pattern": {
        name: "Docker Email Pattern",
        familyName: "Docker",
        pattern: /[\"']?email[\"']?\s*:\s*[\"']([^\"']+)[\"']/gi,
        entropy: 0,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "JotForm API Key": {
        name: "JotForm API Key",
        familyName: "JotForm",
        pattern: /\b([0-9A-Za-z]{32})\b/g,
        entropy: DEFAULT_JOTFORM_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Groq API Key": {
        name: "Groq API Key",
        familyName: "Groq",
        pattern: /\b(gsk_[a-zA-Z0-9]{52})\b/g,
        entropy: DEFAULT_GROQ_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Mailgun Original Token": {
        name: "Mailgun Original Token",
        familyName: "Mailgun",
        pattern: /\b([a-zA-Z0-9-]{72})\b/g,
        entropy: DEFAULT_MAILGUN_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Mailgun Key Token": {
        name: "Mailgun Key Token", 
        familyName: "Mailgun",
        pattern: /\b(key-[a-z0-9]{32})\b/g,
        entropy: DEFAULT_MAILGUN_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Mailgun Hex Token": {
        name: "Mailgun Hex Token",
        familyName: "Mailgun", 
        pattern: /\b([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})\b/g,
        entropy: DEFAULT_MAILGUN_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Mailchimp API Key": {
        name: "Mailchimp API Key",
        familyName: "Mailchimp",
        pattern: /\b([0-9a-f]{32}-us[0-9]{1,2})\b/g,
        entropy: DEFAULT_MAILCHIMP_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "DeepSeek API Key": {
        name: "DeepSeek API Key",
        familyName: "DeepSeek",
        pattern: /\b(sk-[a-zA-Z0-9]{32})\b/g,
        entropy: deepseekConfig.entropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "DeepAI API Key": {
        name: "DeepAI API Key",
        familyName: "DeepAI",
        pattern: /\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b/g,
        entropy: deepaiConfig.patterns.apiKey.entropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Telegram Bot Token": {
        name: "Telegram Bot Token",
        familyName: "Telegram Bot Token",
        pattern: /\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b/g,
        entropy: DEFAULT_TELEGRAM_BOT_TOKEN_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "RapidAPI Key": {
        name: "RapidAPI Key",
        familyName: "RapidAPI",
        pattern: /\b([A-Za-z0-9_-]{50})\b/g,
        entropy: DEFAULT_RAPID_API_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    },
    "Make API Token": {
        name: "Make API Token",
        familyName: "Make",
        pattern: /\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b/g,
        entropy: DEFAULT_MAKE_CONFIG.requiredEntropy,
        isValidityCustomizable: false,
        hasCustomValidity: false,
        validityEndpoints: [],
        global: true
    }
}

storePatterns(patterns);