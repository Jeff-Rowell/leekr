import { Finding } from "../../types/findings.types";

export function getExistingFindings(): Promise<Finding[]> {
    return new Promise((resolve) => {
        chrome.storage.local.get(['findings'], (result) => {
            resolve(result.findings || []);
        });
    });
}