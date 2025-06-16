const ADMIN_KEY_ENDPOINT = "https://api.anthropic.com/v1/organizations/api_keys";
const API_KEY_ENDPOINT = "https://api.anthropic.com/v1/models";
const ENDPOINTS: [string, string][] = [
    ['ADMIN', ADMIN_KEY_ENDPOINT],
    ['USER', API_KEY_ENDPOINT],
];

export async function validateAnthropicCredentials(apiKey: string): Promise<{ valid: boolean; type: string; error: any }> {
    for (const [keyType, endpoint] of ENDPOINTS) {
        try {
            const res = await fetch(endpoint, {
                method: 'GET',
                headers: {
                    'x-api-key': apiKey,
                    'Content-Type': 'application/json',
                    'anthropic-version': '2023-06-01',
                },
            });

            if (res.status === 200) {
                return { valid: true, type: keyType, error: "" };
            }

            if (res.status === 401 || res.status === 404) {
                continue; // try the next endpoint
            }

            return {
                valid: false,
                type: "unknown",
                error: `Unexpected HTTP status ${res.status} from ${endpoint}`,
            };
        } catch (err) {
            if (err instanceof DOMException && err.name === 'AbortError') {
                return { valid: false, type: "unkown", error: 'Request was aborted' };
            }
            return { valid: false, type: "unknown", error: err };
        }
    }
    return {
        valid: true,
        type: 'admin',
        error: null
    };
}