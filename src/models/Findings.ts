import { Finding, FindingDict } from 'src/types/findings.types';

/**
 * Represents all the findings identified by Leekr
 */
class Findings {
    private findings: Finding[];
    private findingsMap: FindingDict[];

    /**
     * Creates a new Findings instance that gets managed by AppContext.
     */
    constructor() {
        this.findings = [];
        this.findingsMap = [];
    }

    /**
     * Adds a new finding if it doesn't aleady exist.
     * @param newFinding - The new finding to add.
     * @returns True if the finding doesn't exist and was added successfuly, false otherwise
     */
    addFinding(newFinding: Finding): boolean {
        if (this.hasFinding(newFinding.fingerprint)) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Removes a finding.
     * @param fingerprint - The fingerprint of the finding to remove.
     * @returns True if the finding exists and was removed successfuly, false otherwise
     */
    removeFinding(fingerprint: string): boolean {
        if (!this.hasFinding(fingerprint)) {
            return false;
        } else {
            const findingsIdx = this.findings.findIndex(obj => obj.fingerprint === fingerprint);
            const findingsMapIdx = this.findingsMap.findIndex(obj => fingerprint in obj);
            if (findingsIdx > -1 && findingsMapIdx > -1) {
                this.findings.splice(findingsIdx, 1);
                this.findingsMap.splice(findingsMapIdx, 1);
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * Retrieves a finding.
     * @param fingerprint - The fingerprint of the finding to retrieve.
     * @returns The Finding object if it exists, null otherwise
     */
    getFinding(fingerprint: string): Finding | null {
        const idx = this.findings.findIndex(obj => obj.fingerprint === fingerprint);
        if (idx > -1) {
            return this.findings[idx]
        } else {
            return null;
        }
    }

    /**
     * Checks if a Finding exists for the provided secret fingerprint.
     * @param fingerprint - The secret fingerprint to check for
     * @returns True if the fingerprint has an associated Finding object, false otherwise
     */
    hasFinding(fingerprint: string): boolean {
        return this.findingsMap.some(findingDict => fingerprint in findingDict);
    }
}