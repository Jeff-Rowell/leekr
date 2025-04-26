import { Finding, FindingDict, Occurrence } from 'src/types/findings.types';

/**
 * Represents all the findings identified by Leekr
 */
export class Findings {
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
     * Gets the length of this Findings instance.
     * @returns The length of this Findings instance.
     */
    get length(): number {
        return this.findings.length;
    }

    /**
     * Applies a function to each element in the Findings array and returns a new 
     * Findings array containing the results.
     * 
     * @param callback The function that is called one time for each Finding in 
     *                 this Findings instance.
     * @param value The current element being processed
     * @param index The position of the current element being processed
     * @returns A new array with each element being the result of the callback function.
     */
    map<U>(callback: (value: Finding, index: number) => U): U[] {
        const result: U[] = [];
        for (let i = 0; i < this.findings.length; i++) {
            result.push(callback(this.findings[i], i));
        }
        return result;
    }

    /**
     * Applies a function to each element in the Findings array and returns a new 
     * Findings array containing the results.
     * 
     * @param callback The function that is called one time for each Finding in 
     *                 this Findings instance.
     * @param item The current element being processed
     * @returns A new array with each element being the result of the callback function.
     */
    forEach(callback: (item: Finding) => void): void {
        for (let i = 0; i < this.findings.length; i++) {
            callback(this.findings[i]);
        }
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
     * 
     * @returns All of the findings
     */
    getAllFindigns(): Finding[] {
        return this.findings;
    }

    /**
     * Checks if a Finding exists for the provided secret fingerprint.
     * @param fingerprint - The secret fingerprint to check for
     * @returns True if the fingerprint has an associated Finding object, false otherwise
     */
    hasFinding(fingerprint: string): boolean {
        return this.findingsMap.some(findingDict => fingerprint in findingDict);
    }

    /**
     * Adds a new Occurrence to an existing Finding if it doesn't aleady exist.
     * @param newOccurrence - The new Occurrence to add.
     * @returns True if the Occurrence doesn't exist and was added to a Finding successfuly, false otherwise
     */
    addOccurrence(newOccurrence: Occurrence): boolean {
        const existingFinding = this.getFinding(newOccurrence.fingerprint);
        if (existingFinding === null) {
            return false;
        }
        for (const existingOccurrence of existingFinding.occurrences) {
            if (existingOccurrence.url === newOccurrence.url) {
                return false;
            } else {
                if (this.isSameOrigin(existingOccurrence.url, newOccurrence.url)) {
                    existingOccurrence.filePath = newOccurrence.filePath;
                    existingOccurrence.url = newOccurrence.url;
                    return false;
                }
            }
        }
        existingFinding.occurrences.add(newOccurrence)
        existingFinding.numOccurrences += 1;
        return true;
    }

    /**
     * Creates a new Finding object given a new Occurrence.
     * @param newOccurrence - The new Occurrence to create a new Finding from.
     * @returns The newly created Finding if the occurrence doesn't exist, null otherwise
     */
    createFindingFromOccurrence(newOccurrence: Occurrence): Finding | null {
        if (this.hasFinding(newOccurrence.fingerprint)) {
            return null;
        }
        const newFinding: Finding = {
            numOccurrences: 1,
            secretType: newOccurrence.secretType,
            secretValue: newOccurrence.secretValue,
            validity: 'valid',
            validatedAt: new Date().toISOString(),
            fingerprint: newOccurrence.fingerprint,
            occurrences: new Set([newOccurrence])
        }
        // the occurrence is set here, but it gets unset later on somewhere
        console.log('newFinding = ', newFinding);
        this.findings.push(newFinding);
        const newFindingDict: FindingDict = {}
        newFindingDict[newFinding.fingerprint] = newFinding.occurrences;
        this.findingsMap.push(newFindingDict);
        return newFinding;
    }

    /**
     * Checks if two URLs share the same origin.
     * @param url1 - The first URL to compare
     * @param url2 - The second URL to compare
     * @returns True if the URLs share the same origin, false otherwise
     */
    private isSameOrigin(url1: string, url2: string): boolean {
        try {
            const u1 = new URL(url1);
            const u2 = new URL(url2);
            return u1.origin === u2.origin;
        } catch (e) {
            return false;
        }
    }
}