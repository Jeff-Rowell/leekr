const baseUrls = [
    'https://eu1.make.com/api/v2/',
    'https://eu2.make.com/api/v2/',
    'https://us1.make.com/api/v2/',
    'https://us2.make.com/api/v2/',
    'https://eu1.make.celonis.com/api/v2/',
    'https://us1.make.celonis.com/api/v2/',
]

export const validateMakeApiToken = async (apiToken: string): Promise<{ valid: boolean; error?: string }> => {
    try {
        const validityResponse = { valid: false } 
        
        for (const base of baseUrls) {
            
            const response = await fetch(base + 'users/me/current-authorization', {
                method: 'GET',
                headers: {
                    'Authorization': `Token ${apiToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.status === 200) {
                try {
                    const data = await response.json();
                    
                    if (Array.isArray(data)) {
                        validityResponse.valid = true;
                        break;
                    }
                } catch (jsonError) {
                    const errorMessage = jsonError instanceof Error ? jsonError.message : "Unknown error occurred";
                }
            }
        }
        
        return validityResponse;
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
        return {
            valid: false,
            error: errorMessage
        };
    }
};