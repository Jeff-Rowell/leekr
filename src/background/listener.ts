import { findSecrets } from './scanner';

chrome.webRequest.onCompleted.addListener(
    async (details) => {
        if (!details.url.startsWith("chrome-extension") && ((details.url.endsWith('.js') || details.url.endsWith('.mjs') || details.url.endsWith('.cjs')))) {
            try {
                const response = await fetch(details.url);
                const content = await response.text();
                await findSecrets(content, details.url);
            } catch (err) {
                console.error('Error scanning JS file:', err);
            }
        }
    },
    { urls: ['<all_urls>'], types: ['script'] }
);
