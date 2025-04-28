import { findSecrets } from './scanner';
import { Finding } from 'src/types/findings.types';
import { mergeFindings } from './utils/mergeFindings';
import { retrieveFindings, storeFindings } from './utils/common';

chrome.webRequest.onCompleted.addListener(
    async (details) => {
        if (!details.url.startsWith("chrome-extension") && ((details.url.endsWith('.js') || details.url.endsWith('.mjs') || details.url.endsWith('.cjs')))) {
            try {
                const response = await fetch(details.url);
                const content = await response.text();
                const newFindings = await findSecrets(content, details.url);
                const existingFindings: Finding[] = await retrieveFindings() || [];
                const updatedFindings: Finding[] = await mergeFindings(existingFindings, newFindings, details.url);
                const brandNewFindings = updatedFindings.filter(finding =>
                    !existingFindings.some(existingFinding =>
                        existingFinding.fingerprint === finding.fingerprint
                    )
                );
                storeFindings(updatedFindings);
                chrome.storage.local.set({ "notifications": brandNewFindings.length.toString() }, function () {
                    if (brandNewFindings.length > 0) {
                        chrome.action.setBadgeText({ text: brandNewFindings.length.toString() });
                        chrome.action.setBadgeBackgroundColor({ color: '#FF141A' });
                        chrome.runtime.sendMessage({
                            type: 'NEW_NOTIFICATION',
                            payload: brandNewFindings.length.toString()
                        }).catch(() => {
                            chrome.storage.local.get(null);
                        });
                    }
                });

            } catch (err) {
                console.error('Error scanning JS file:', err);
            }
        }
    },
    { urls: ['<all_urls>'], types: ['script'] }
);
