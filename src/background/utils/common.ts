import { Finding } from "../../types/findings.types";

export function getExistingFindings(): Promise<Finding[]> {
    return new Promise(async (resolve) => {
        const findings = await retrieveFindings();
        resolve(findings || []);
    });
}

export function serializeFindings(findings: Finding[]): any[] {
    return findings.map(finding => ({
        ...finding,
        occurrences: Array.from(finding.occurrences)
    }));
}

export function deserializeFindings(serializedFindings: any[]): Finding[] {
    return serializedFindings.map(finding => ({
        ...finding,
        occurrences: new Set(finding.occurrences)
    }));
}


export function storeFindings(findings: Finding[]): Promise<void> {
    const serialized = serializeFindings(findings);
    return new Promise((resolve) => {
        chrome.storage.local.set({ findings: serialized }, resolve);
    });
}

export function retrieveFindings(): Promise<Finding[]> {
    return new Promise((resolve) => {
        chrome.storage.local.get(['findings'], (result) => {
            if (result.findings) {
                const deserialized = deserializeFindings(result.findings);
                resolve(deserialized);
            } else {
                resolve([]);
            }
        });
    });
}