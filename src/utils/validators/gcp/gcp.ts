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

        // First do structural validation
        const structureValidation = validateServiceAccountStructure(credentials);
        if (!structureValidation.valid) {
            return structureValidation;
        }

        // Now do actual validation by attempting to get an access token
        try {
            const isValid = await verifyGcpCredentials(credentials);
            if (isValid) {
                return { valid: true, type: 'SERVICE_ACCOUNT', error: '' };
            } else {
                return { valid: false, type: 'SERVICE_ACCOUNT', error: 'Invalid credentials - authentication failed' };
            }
        } catch (verificationError: any) {
            // Check for specific error types
            if (verificationError.message && (
                verificationError.message.includes('invalid_grant') || 
                verificationError.message.includes('invalid_client') ||
                verificationError.message.includes('disabled') ||
                verificationError.message.includes('deleted'))) {
                return { valid: false, type: 'SERVICE_ACCOUNT', error: 'Service account is disabled or deleted' };
            }
            return { valid: false, type: 'SERVICE_ACCOUNT', error: 'Verification failed' };
        }

    } catch (error) {
        return { valid: false, type: 'unknown', error: error };
    }
}

async function verifyGcpCredentials(credentials: GcpCredentials): Promise<boolean> {
    try {
        // Create JWT assertion for OAuth2 flow
        const now = Math.floor(Date.now() / 1000);
        
        // Create the JWT header
        const header = {
            alg: 'RS256',
            typ: 'JWT'
        };

        // Create the JWT payload
        const payload = {
            iss: credentials.client_email,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            aud: GCP_TOKEN_ENDPOINT,
            exp: now + 3600,
            iat: now
        };

        // Encode header and payload
        const encodedHeader = base64UrlEncode(JSON.stringify(header));
        const encodedPayload = base64UrlEncode(JSON.stringify(payload));
        
        // Create the signing input
        const signingInput = `${encodedHeader}.${encodedPayload}`;
        
        // Sign the JWT using the private key
        const signature = await signJWT(signingInput, credentials.private_key);
        
        // Create the complete JWT
        const jwt = `${signingInput}.${signature}`;
        
        // Exchange JWT for access token
        const tokenResponse = await fetch(GCP_TOKEN_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                assertion: jwt
            })
        });

        if (!tokenResponse.ok) {
            const errorText = await tokenResponse.text();
            throw new Error(`Token request failed: ${tokenResponse.status} ${errorText}`);
        }

        const tokenData = await tokenResponse.json();
        
        // If we get an access token, the credentials are valid
        return !!(tokenData.access_token);
        
    } catch (error: any) {
        // Re-throw the error to be handled by the caller
        throw error;
    }
}

async function signJWT(signingInput: string, privateKey: string): Promise<string> {
    try {
        // Clean up the private key
        const cleanKey = privateKey
            .replace(/\\n/g, '\n')
            .replace(/-----BEGIN PRIVATE KEY-----/, '-----BEGIN PRIVATE KEY-----\n')
            .replace(/-----END PRIVATE KEY-----/, '\n-----END PRIVATE KEY-----')
            .trim();

        // Convert PEM to DER format for Web Crypto API
        const pemHeader = '-----BEGIN PRIVATE KEY-----';
        const pemFooter = '-----END PRIVATE KEY-----';
        
        if (!cleanKey.includes(pemHeader) || !cleanKey.includes(pemFooter)) {
            throw new Error('Invalid private key format');
        }

        const keyData = cleanKey
            .replace(pemHeader, '')
            .replace(pemFooter, '')
            .replace(/\s/g, '');

        // Convert base64 to ArrayBuffer
        const binaryKey = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));

        // Import the private key
        const cryptoKey = await crypto.subtle.importKey(
            'pkcs8',
            binaryKey,
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256'
            },
            false,
            ['sign']
        );

        // Sign the data
        const signature = await crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            cryptoKey,
            new TextEncoder().encode(signingInput)
        );

        // Convert signature to base64url
        return base64UrlEncode(new Uint8Array(signature));
        
    } catch (error: any) {
        throw new Error(`JWT signing failed: ${error.message}`);
    }
}

function base64UrlEncode(data: string | Uint8Array): string {
    let base64: string;
    
    if (typeof data === 'string') {
        base64 = btoa(data);
    } else {
        // Convert Uint8Array to base64
        base64 = btoa(String.fromCharCode(...Array.from(data)));
    }
    
    // Convert base64 to base64url
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
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