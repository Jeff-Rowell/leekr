export const HUGGINGFACE_RESOURCE_TYPES = {
    API_KEY: "API Key"
} as const;

export const DEFAULT_HUGGINGFACE_API_KEY_CONFIG = {
    requiredEntropy: 2.5
} as const;

export const HUGGINGFACE_CONFIG = {
    name: "Hugging Face",
    description: "Hugging Face is a platform for natural language processing tasks and model hosting. Hugging Face API keys can be used to access various services and resources on the platform.",
    resourceTypes: HUGGINGFACE_RESOURCE_TYPES,
    keywords: ["hf_", "api_org_"],
    pattern: /\b(?:hf_|api_org_)[a-zA-Z0-9]{34}\b/g
} as const;