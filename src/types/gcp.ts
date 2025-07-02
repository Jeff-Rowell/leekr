import { Occurrence } from './findings.types';

export interface GcpSecretValue {
    match: {
        service_account_key: string;
        type?: string;
        project_id?: string;
        private_key_id?: string;
        private_key?: string;
        client_email?: string;
        client_id?: string;
        auth_uri?: string;
        token_uri?: string;
        auth_provider_x509_cert_url?: string;
        client_x509_cert_url?: string;
    };
}

export interface GcpOccurrence extends Occurrence {
    secretValue: GcpSecretValue;
    type: string;
    validity?: string;
}

export interface GcpCredentials {
    type: string;
    project_id: string;
    private_key_id: string;
    private_key: string;
    client_email: string;
    client_id: string;
    auth_uri: string;
    token_uri: string;
    auth_provider_x509_cert_url: string;
    client_x509_cert_url: string;
}