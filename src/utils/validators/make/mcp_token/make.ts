export async function validateMakeMcpToken(
    fullUrl: string
): Promise<{
    valid: boolean;
    error?: string;
}> {
    try {
        const response = await fetch(fullUrl, {
            method: 'GET',
            headers: {
                'Accept': 'text/event-stream',
                'Cache-Control': 'no-cache'
            }
        });

        if (response.status === 200) {
            return { valid: true };
        } else if (response.status === 401) {
            return { valid: false };
        } else if (response.status === 403) {
            return { valid: false };
        } else if (response.status === 404) {
            return { valid: false };
        } else if (response.status >= 500) {
            return { valid: false };
        } else {
            return { valid: false };
        }
    } catch (error) {
        if (error instanceof TypeError) {
            return {
                valid: false,
                error: error.message
            };
        } else if (error instanceof Error) {
            return {
                valid: false,
                error: error.message
            };
        } else {
            return {
                valid: false,
                error: String(error)
            };
        }
    }
}