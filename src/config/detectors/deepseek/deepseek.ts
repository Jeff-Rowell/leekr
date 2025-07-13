export const deepseekConfig = {
    entropy: 3.5,
    api: {
        baseUrl: "https://api.deepseek.com",
        endpoints: {
            balance: "/user/balance"
        },
        timeout: 10000
    },
    validation: {
        enabled: true,
        retries: 2
    }
};