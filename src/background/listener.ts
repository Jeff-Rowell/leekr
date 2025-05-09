import { findSecrets } from './scanner';
import { Finding } from 'src/types/findings.types';
import { mergeFindings } from './utils/mergeFindings';
import { retrieveFindings, storeFindings } from './utils/common';
import { Suffix } from '../types/suffix.types';


chrome.webRequest.onCompleted.addListener(
    async (details) => {
        const results = await chrome.storage.local.get(['suffixes']);
        var suffixValues;
        if (results.suffixes) {
            suffixValues = results.suffixes.map((suffix: Suffix) => suffix.value);
        } else {
            suffixValues = [];
        }
        if (!details.url.startsWith("chrome-extension") && suffixValues.some((suffix: string) => details.url.endsWith(suffix))) {
            try {
                const response = await fetch(details.url);
                const bundleContent = await response.text();
                const newFindings = await findSecrets(bundleContent, details.url);
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
