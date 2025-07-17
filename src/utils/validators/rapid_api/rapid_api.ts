const RAPID_API_ENDPOINT = "https://covid-193.p.rapidapi.com/countries";

export async function validateRapidApiCredentials(apiKey: string): Promise<{ valid: boolean; type: string; error: any }> {
    try {
        const res = await fetch(RAPID_API_ENDPOINT, {
            method: 'GET',
            headers: {
                'x-rapidapi-key': apiKey,
                'x-rapidapi-host': 'covid-193.p.rapidapi.com',
                'Content-Type': 'application/json',
            },
        });

        if (res.status >= 200 && res.status < 300) {
            return { valid: true, type: 'API_KEY', error: null };
        }

        if (res.status === 401 || res.status === 403) {
            return { valid: false, type: 'API_KEY', error: 'Unauthorized' };
        }

        return {
            valid: false,
            type: "unknown",
            error: `Unexpected HTTP status ${res.status} from ${RAPID_API_ENDPOINT}`,
        };
    } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') {
            return { valid: false, type: "unknown", error: 'Request was aborted' };
        }
        return { valid: false, type: "unknown", error: err };
    }
}