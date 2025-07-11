export const deepaiConfig = {
    patterns: {
        apiKey: {
            pattern: /([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})/g,
            entropy: 3.5
        }
    },
    api: {
        baseUrl: "https://api.deepai.org",
        endpoints: {
            textTagging: "/api/text-tagging"
        },
        timeout: 10000
    },
    validation: {
        enabled: true,
        retries: 2
    }
};