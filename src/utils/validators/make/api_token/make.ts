const baseUrls = [
    'https://eu1.make.com/api/v2/',
    'https://eu2.make.com/api/v2/',
    'https://us1.make.com/api/v2/',
    'https://us2.make.com/api/v2/',
    'https://eu1.make.celonis.com/api/v2/',
    'https://eu2.make.celonis.com/api/v2/',
]

export const validateMakeApiToken = async (apiToken: string): Promise<{ valid: boolean; error?: string }> => {
    console.log('[Make Validator] Starting validation for token:', apiToken);
    
    try {
        const validityResponse = { valid: false } 
        
        for (const base of baseUrls) {
            console.log('[Make Validator] Trying base URL:', base);
            
            const response = await fetch(base + 'users/me/current-authorization', {
                method: 'GET',
                headers: {
                    'Authorization': `Token ${apiToken}`,
                    'Content-Type': 'application/json'
                }
            });

            console.log('[Make Validator] Response status:', response.status, 'for base:', base);

            if (response.status === 200) {
                try {
                    const data = await response.json();
                    console.log('[Make Validator] Response data:', data, 'is array:', Array.isArray(data));
                    
                    if (Array.isArray(data)) {
                        validityResponse.valid = true;
                        console.log('[Make Validator] Token validated successfully with base:', base);
                        break;
                    } else {
                        console.log('[Make Validator] Response data is not an array, continuing to next base');
                    }
                } catch (jsonError) {
                    console.log('[Make Validator] JSON parsing error:', jsonError);
                    const errorMessage = jsonError instanceof Error ? jsonError.message : "Unknown error occurred";
                    console.log('[Make Validator] JSON error message:', errorMessage);
                }
            }
        }
        
        console.log('[Make Validator] Final validation result:', validityResponse);
        return validityResponse;
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
        console.log('[Make Validator] General error:', errorMessage);
        return {
            valid: false,
            error: errorMessage
        };
    }
};