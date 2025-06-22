import { OpenAIValidationResult } from '../../../types/openai';

export async function validateOpenAICredentials(apiKey: string): Promise<OpenAIValidationResult> {
    try {
        const response = await fetch('https://api.openai.com/v1/me', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Authorization': `Bearer ${apiKey}`,
            },
        });

        if (response.status === 200) {
            const data = await response.json();
            
            const result: OpenAIValidationResult = {
                valid: true,
                type: 'USER',
                error: '',
                id: data.id,
                totalOrgs: data.orgs?.data?.length || 0,
                mfaEnabled: data.mfa_flag_enabled,
                createdAt: data.created ? new Date(data.created * 1000).toISOString() : undefined,
            };

            if (data.orgs?.data?.length > 0) {
                const firstOrg = data.orgs.data[0];
                result.description = firstOrg.description;
                result.isPersonal = firstOrg.personal;
                result.isDefault = firstOrg.is_default;
            }

            return result;
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