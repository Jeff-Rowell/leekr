import { ArtifactoryValidationResult } from '../../../types/artifactory';

export async function validateArtifactoryCredentials(
    apiKey: string, 
    url?: string
): Promise<ArtifactoryValidationResult> {
    try {
        // If no URL provided, try to extract from common Artifactory URL patterns
        let artifactoryUrl = url;
        if (!artifactoryUrl) {
            // Return invalid if no URL is provided since Artifactory requires both token and URL
            return {
                valid: false,
                error: 'Artifactory URL is required for validation'
            };
        }

        // Ensure URL has proper protocol
        if (!artifactoryUrl.startsWith('http://') && !artifactoryUrl.startsWith('https://')) {
            artifactoryUrl = 'https://' + artifactoryUrl;
        }

        // Construct the API endpoint
        const endpoint = `${artifactoryUrl}/artifactory/api/storageinfo`;

        const response = await fetch(endpoint, {
            method: 'GET',
            headers: {
                'X-JFrog-Art-Api': apiKey,
                'Content-Type': 'application/json'
            }
        });

        if (response.ok) {
            const data = await response.json();
            return {
                valid: true,
                error: '',
                url: artifactoryUrl,
                tokenInfo: 'Valid Artifactory access token',
                permissions: ['read'] // Basic permission assumed for valid token
            };
        } else if (response.status === 403) {
            // Forbidden - token exists but lacks permissions
            return {
                valid: false,
                error: 'Token exists but lacks required permissions',
                url: artifactoryUrl
            };
        } else if (response.status === 401) {
            // Unauthorized - invalid token
            return {
                valid: false,
                error: 'Invalid Artifactory access token',
                url: artifactoryUrl
            };
        } else {
            return {
                valid: false,
                error: `HTTP ${response.status}: ${response.statusText}`,
                url: artifactoryUrl
            };
        }
    } catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : 'Unknown validation error'
        };
    }
}