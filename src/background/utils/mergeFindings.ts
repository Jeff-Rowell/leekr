import { Finding } from "../../types/findings.types";

export async function mergeFindings(existingFindings: Finding[], newFindings: Finding[], currentUrl: string): Promise<Finding[]> {
    const copyOfExistingFindings = await deepCopyFindings(existingFindings);

    for (const newFinding of newFindings) {
        const existingFindingIndex = copyOfExistingFindings.findIndex(
            finding => finding.fingerprint === newFinding.fingerprint
        );

        if (existingFindingIndex !== -1) {
            const existingFinding = copyOfExistingFindings[existingFindingIndex];
            const newOccurrence = Array.from(newFinding.occurrences)[0];
            let occurrenceUpdated = false;

            for (const existingOccurrence of existingFinding.occurrences) {
                if (await isSameOrigin(existingOccurrence.url, newOccurrence.url)) {
                    existingOccurrence.filePath = newOccurrence.filePath;
                    existingOccurrence.url = newOccurrence.url;
                    occurrenceUpdated = true;
                    break;
                }
            }

            if (!occurrenceUpdated) {
                existingFinding.occurrences.add(newOccurrence);
                existingFinding.numOccurrences = existingFinding.occurrences.size;
            }
        } else {
            copyOfExistingFindings.push(newFinding);
        }
    }

    return copyOfExistingFindings;
}

async function deepCopyFindings(findings: Finding[]): Promise<Finding[]> {
    return findings.map(finding => {
        const occurrencesArray = Array.from(finding.occurrences);
        const copiedOccurrences = occurrencesArray.map(occurrence => ({ ...occurrence }));
        return {
            ...finding,
            occurrences: new Set(copiedOccurrences)
        };
    });
}

async function isSameOrigin(url1: string, url2: string): Promise<boolean> {
    try {
        const u1 = new URL(url1);
        const u2 = new URL(url2);
        return u1.origin === u2.origin;
    } catch (e) {
        return false;
    }
}