export const DEFAULT_ARTIFACTORY_ACCESS_TOKEN_CONFIG = {
    requiredEntropy: 4.0
} as const;

export const DEFAULT_ARTIFACTORY_URL_CONFIG = {
    requiredEntropy: 0.0
} as const;

export const ARTIFACTORY_CONFIG = {
    name: "Artifactory",
    description: "Artifactory is a repository manager that supports all major package formats. Artifactory access tokens can be used to authenticate and perform operations on repositories."
} as const;

export const ARTIFACTORY_RESOURCE_TYPES = {
    ACCESS_TOKEN: "Access Token"
} as const;