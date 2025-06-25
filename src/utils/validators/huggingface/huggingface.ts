import { HuggingFaceValidationResult, HuggingFaceWhoamiResponse } from '../../../types/huggingface';

export async function validateHuggingFaceCredentials(apiKey: string): Promise<HuggingFaceValidationResult> {
    try {
        const response = await fetch('https://huggingface.co/api/whoami-v2', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.status >= 200 && response.status < 300) {
            const data: HuggingFaceWhoamiResponse = await response.json();
            
            let tokenInfo = 'Unknown Token Type';
            let type: 'USER' | 'ORGANIZATION' = 'USER';
            
            if (data.auth.accessToken?.displayName || data.auth.accessToken?.role) {
                // hf_xxxx token
                const t = data.auth.accessToken;
                if (t.displayName && t.role) {
                    tokenInfo = `${t.displayName} (${t.role})`;
                } else if (t.displayName) {
                    tokenInfo = t.displayName;
                } else if (t.role) {
                    tokenInfo = `(${t.role})`;
                }
            } else if (data.auth.type) {
                // api_org_xxxx token
                tokenInfo = data.auth.type;
                type = 'ORGANIZATION';
            }

            const organizations = data.orgs?.map(org => `${org.name}:${org.roleInOrg}`) || [];

            return {
                valid: true,
                type: type,
                error: '',
                username: data.name,
                email: data.email,
                tokenInfo: tokenInfo,
                organizations: organizations
            };
        } else if (response.status === 401) {
            return {
                valid: false,
                type: 'unknown',
                error: 'Invalid API key',
            };
        } else {
            return {
                valid: false,
                type: 'unknown',
                error: `Unexpected HTTP response status ${response.status}`,
            };
        }
    } catch (error) {
        return {
            valid: false,
            type: 'unknown',
            error: error instanceof Error ? error.message : 'Unknown error occurred',
        };
    }
}