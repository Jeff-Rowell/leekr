const API_KEY_ENDPOINT = "https://api.smith.langchain.com/api/v1/api-key";

export async function validateLangsmithCredentials(apiKey: string): Promise<{ valid: boolean; type: string; error: any }> {
    try {
        const res = await fetch(API_KEY_ENDPOINT, {
            method: 'GET',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json',
            },
        });

        if (res.status === 200) {
            const keyType = apiKey.startsWith('lsv2_pt_') ? 'personal' : 'service';
            return { valid: true, type: keyType, error: "" };
        }

        if (res.status === 401 || res.status === 403) {
            return { valid: false, type: "unknown", error: "Unauthorized" };
        }

        return {
            valid: false,
            type: "unknown",
            error: `Unexpected HTTP status ${res.status}`,
        };
    } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') {
            return { valid: false, type: "unknown", error: 'Request was aborted' };
        }
        return { valid: false, type: "unknown", error: err };
    }
}