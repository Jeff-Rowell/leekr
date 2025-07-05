import { DockerCredentials, DockerAuths, DockerAuth } from '../../../types/docker';

const EXAMPLE_REGISTRIES = new Set([
    'https://index.docker.io/v1/',
    'registry.hostname.com',
    'registry.example.com:5000',
    'registry2.example.com:5000',
    'your.private.registry.example.com'
]);

export async function validateDockerCredentials(authConfig: string): Promise<{ valid: boolean; type: string; error: any }> {
    try {
        // Parse the Docker auth config
        let dockerAuths: DockerAuths;
        try {
            dockerAuths = JSON.parse(authConfig);
        } catch (parseError) {
            return { valid: false, type: 'unknown', error: 'Invalid JSON format' };
        }

        // Validate structure
        if (!dockerAuths.auths || typeof dockerAuths.auths !== 'object') {
            return { valid: false, type: 'unknown', error: 'Missing auths object' };
        }

        if (Object.keys(dockerAuths.auths).length === 0) {
            return { valid: false, type: 'unknown', error: 'No registry configurations found' };
        }

        // Check each registry configuration
        for (const [registry, auth] of Object.entries(dockerAuths.auths)) {
            // Skip known example registries
            if (EXAMPLE_REGISTRIES.has(registry)) {
                continue;
            }

            // Validate auth structure
            const authValidation = validateAuthStructure(auth);
            if (!authValidation.valid) {
                return authValidation;
            }

            // Extract credentials
            const credentials = extractCredentials(registry, auth);
            if (!credentials) {
                continue;
            }

            // Attempt to verify credentials with the registry
            try {
                const isValid = await verifyDockerCredentials(credentials);
                if (isValid) {
                    return { valid: true, type: 'REGISTRY', error: '' };
                }
            } catch (verificationError: any) {
                // If verification fails, continue to next registry or return error
                if (verificationError.message && verificationError.message.includes('unauthorized')) {
                    return { valid: false, type: 'REGISTRY', error: 'Invalid credentials - authentication failed' };
                }
                return { valid: false, type: 'REGISTRY', error: 'Verification failed' };
            }
        }

        return { valid: false, type: 'REGISTRY', error: 'No valid registry credentials found' };

    } catch (error) {
        return { valid: false, type: 'unknown', error: error };
    }
}

function validateAuthStructure(auth: DockerAuth): { valid: boolean; type: string; error: string } {
    if (!auth || typeof auth !== 'object') {
        return { valid: false, type: 'unknown', error: 'Invalid auth object' };
    }

    // Must have either auth field or username/password combination
    const hasAuth = auth.auth && typeof auth.auth === 'string' && auth.auth.length > 0;
    const hasUserPass = auth.username && typeof auth.username === 'string' && 
                        auth.password && typeof auth.password === 'string';

    if (!hasAuth && !hasUserPass) {
        return { valid: false, type: 'unknown', error: 'Missing auth credentials' };
    }

    return { valid: true, type: 'REGISTRY', error: '' };
}

function extractCredentials(registry: string, auth: DockerAuth): DockerCredentials | null {
    let username = '';
    let password = '';

    // Handle case where credentials are in username/password fields
    if (auth.username && auth.password) {
        username = auth.username;
        password = auth.password;
    }

    // Handle case where credentials are in base64 auth field
    if (auth.auth) {
        try {
            const decoded = atob(auth.auth);
            const parts = decoded.split(':');
            if (parts.length === 2) {
                // If we already have username/password, verify they match
                if (username && password) {
                    if (parts[0] !== username || parts[1] !== password) {
                        // Credentials don't match, use the auth field values
                        username = parts[0];
                        password = parts[1];
                    }
                } else {
                    username = parts[0];
                    password = parts[1];
                }
            }
        } catch (decodeError) {
            return null;
        }
    }

    if (!username || !password) {
        return null;
    }

    // Create base64 auth string
    const base64Auth = btoa(`${username}:${password}`);

    return {
        registry,
        auth: base64Auth,
        username,
        password
    };
}

async function verifyDockerCredentials(credentials: DockerCredentials): Promise<boolean> {
    // Normalize registry URL
    let registryUrl = credentials.registry;
    
    // Handle docker.io special case
    if (registryUrl.toLowerCase() === 'docker.io') {
        registryUrl = 'index.docker.io';
    }

    // Remove trailing slash
    registryUrl = registryUrl.replace(/\/$/, '');
    
    // Add https if no protocol specified
    if (!registryUrl.startsWith('http://') && !registryUrl.startsWith('https://')) {
        registryUrl = 'https://' + registryUrl;
    }
    
    // Add /v2/ path for Docker Registry API v2
    registryUrl += '/v2/';

    try {
        // Make initial request to registry API
        const response = await fetch(registryUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Basic ${credentials.auth}`,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        // Handle response
        switch (response.status) {
            case 200:
                // Success - credentials are valid
                const body = await response.text();
                try {
                    JSON.parse(body);
                    return true;
                } catch {
                    // Even if response isn't JSON, 200 status indicates valid auth
                    return true;
                }
            
            case 401:
                // Handle token authentication flow for registries that require it
                const wwwAuth = response.headers.get('Www-Authenticate');
                if (wwwAuth && wwwAuth.startsWith('Bearer')) {
                    return await handleBearerAuth(wwwAuth, credentials);
                }
                return false;
            
            case 404:
                // Registry might not exist or endpoint not found
                return false;
            
            default:
                return false;
        }
    } catch (error) {
        throw error;
    }
}

async function handleBearerAuth(wwwAuthHeader: string, credentials: DockerCredentials): Promise<boolean> {
    try {
        // Parse WWW-Authenticate header
        const authParams = parseAuthenticateHeader(wwwAuthHeader);
        const realm = authParams.realm;
        
        if (!realm) {
            return false;
        }

        // Build token request URL
        const tokenUrl = new URL(realm);
        const searchParams = new URLSearchParams();
        searchParams.set('account', credentials.username);
        if (authParams.service) {
            searchParams.set('service', authParams.service);
        }
        tokenUrl.search = searchParams.toString();

        // Request token
        const tokenResponse = await fetch(tokenUrl.toString(), {
            method: 'GET',
            headers: {
                'Authorization': `Basic ${credentials.auth}`,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        return tokenResponse.status === 200;
    } catch {
        return false;
    }
}

function parseAuthenticateHeader(headerValue: string): Record<string, string> {
    const authParams: Record<string, string> = {};
    
    const parts = headerValue.split(' ');
    if (parts.length < 2) {
        return authParams;
    }
    
    authParams.scheme = parts[0];
    
    const paramString = parts.slice(1).join(' ');
    const paramParts = paramString.split(',');
    
    for (const part of paramParts) {
        const keyValue = part.trim().split('=');
        if (keyValue.length === 2) {
            const key = keyValue[0].trim();
            const value = keyValue[1].trim().replace(/^"/, '').replace(/"$/, '');
            authParams[key] = value;
        }
    }
    
    return authParams;
}