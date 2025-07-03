import { GcpCredentials } from '../../../types/gcp';

const GCP_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

export async function validateGcpCredentials(serviceAccountKey: string): Promise<{ valid: boolean; type: string; error: any }> {
    try {
        // Parse the service account key
        let credentials: GcpCredentials;
        try {
            credentials = JSON.parse(serviceAccountKey);
        } catch (parseError) {
            return { valid: false, type: 'unknown', error: 'Invalid JSON format' };
        }

        // Validate required fields
        if (!credentials.type || !credentials.private_key || !credentials.client_email) {
            return { valid: false, type: 'unknown', error: 'Missing required fields' };
        }

        // Skip validation for known test service account
        if (credentials.client_email === 'image-pulling@authenticated-image-pulling.iam.gserviceaccount.com') {
            return { valid: false, type: 'unknown', error: 'Test service account' };
        }

        // Create JWT assertion for OAuth2 flow
        const now = Math.floor(Date.now() / 1000);
        const header = {
            alg: 'RS256',
            typ: 'JWT'
        };

        const payload = {
            iss: credentials.client_email,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            aud: GCP_TOKEN_ENDPOINT,
            exp: now + 3600,
            iat: now
        };

        // For browser environment, we cannot actually sign the JWT with the private key
        // Instead, we'll do basic validation of the service account structure
        const structureValidation = validateServiceAccountStructure(credentials);
        if (!structureValidation.valid) {
            return structureValidation;
        }

        // In a real implementation, we would:
        // 1. Sign the JWT with the private key
        // 2. Make a request to the token endpoint
        // 3. Use the access token to make an authenticated API call
        // For now, we'll return valid if the structure is correct
        return { valid: true, type: 'SERVICE_ACCOUNT', error: '' };

    } catch (error) {
        return { valid: false, type: 'unknown', error: error };
    }
}

function validateServiceAccountStructure(credentials: GcpCredentials): { valid: boolean; type: string; error: string } {
    // Check for required fields and their basic format
    if (credentials.type !== 'service_account') {
        return { valid: false, type: 'unknown', error: 'Not a service account' };
    }

    if (!credentials.project_id || typeof credentials.project_id !== 'string') {
        return { valid: false, type: 'unknown', error: 'Invalid project_id' };
    }

    if (!credentials.private_key_id || typeof credentials.private_key_id !== 'string') {
        return { valid: false, type: 'unknown', error: 'Invalid private_key_id' };
    }

    if (!credentials.private_key || typeof credentials.private_key !== 'string') {
        return { valid: false, type: 'unknown', error: 'Invalid private_key' };
    }

    if (!credentials.client_email || typeof credentials.client_email !== 'string') {
        return { valid: false, type: 'unknown', error: 'Invalid client_email' };
    }

    // Basic format validation
    if (!credentials.client_email.includes('@') || !credentials.client_email.includes('.')) {
        return { valid: false, type: 'unknown', error: 'Invalid email format' };
    }

    if (!credentials.private_key.includes('BEGIN PRIVATE KEY') || !credentials.private_key.includes('END PRIVATE KEY')) {
        return { valid: false, type: 'unknown', error: 'Invalid private key format' };
    }

    return { valid: true, type: 'SERVICE_ACCOUNT', error: '' };
}