import { matchPatterns } from './patternMatcher';
import { Finding } from 'src/types/findings.types';

chrome.webRequest.onCompleted.addListener(
    async (details) => {
        if (!details.url.startsWith("chrome-extension") && ((details.url.endsWith('.js') || details.url.endsWith('.mjs') || details.url.endsWith('.cjs')))) {
            try {
                const response = await fetch(details.url);
                const content = await response.text();
                const findings = matchPatterns(content, details.url);

                chrome.storage.local.get(['findings'], function (result) {
                    let allFindings = result.findings || [];

                    const uniqueNewFindings = findings.filter(newFinding =>
                        !allFindings.some((existing: Finding) =>
                            existing.fingerprint === newFinding.fingerprint
                        )
                    );

                    allFindings = [...allFindings, ...uniqueNewFindings];
                    chrome.storage.local.set({ "findings": allFindings }, function () {
                        chrome.runtime.sendMessage({
                            type: 'NEW_FINDINGS',
                            payload: allFindings,
                        }).catch(() => {
                            chrome.storage.local.get(null);
                        });
                    });

                    chrome.storage.local.set({ "notifications": uniqueNewFindings.length.toString() }, function () {
                        if (uniqueNewFindings.length > 0) {
                            chrome.action.setBadgeText({ text: uniqueNewFindings.length.toString() });
                            chrome.action.setBadgeBackgroundColor({ color: '#FF141A' });
                        }

                        chrome.runtime.sendMessage({
                            type: 'NEW_NOTIFICATION',
                            payload: uniqueNewFindings.length.toString()
                        }).catch(() => {
                            chrome.storage.local.get(null);
                        });
                    })
                });
            } catch (err) {
                console.error('Error scanning JS file:', err);
            }
        }
    },
    { urls: ['<all_urls>'], types: ['script'] }
);
