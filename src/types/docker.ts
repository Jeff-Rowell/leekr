import { Occurrence } from './findings.types';

export interface DockerSecretValue {
    match: {
        registry: string;
        auth: string;
        username?: string;
        password?: string;
        email?: string;
    };
}

export interface DockerOccurrence extends Occurrence {
    secretValue: DockerSecretValue;
    type: string;
    validity?: string;
}

export interface DockerAuth {
    auth?: string;
    username?: string;
    password?: string;
    email?: string;
}

export interface DockerAuths {
    auths: Record<string, DockerAuth>;
}

export interface DockerCredentials {
    registry: string;
    auth: string;
    username: string;
    password: string;
}

export interface DockerDetectorConfig {
    requiredEntropy: number;
}