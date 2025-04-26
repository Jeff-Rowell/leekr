import { FindingsState } from '../types/app.types';
import { Finding, Occurrence, FindingDict } from '../types/findings.types';

/**
 * Represents all the findings identified by Leekr
 */
export class Findings {
    private state: FindingsState;

    /**
     * Creates a new Findings instance that gets managed by AppContext.
     */
    constructor() {
        this.state = {
            activeTab: "Findings",
            findings: [],
            findingsMap: [],
            notifications: ""
        };
        this.loadFromStorage();
    }

    /**
     * Loads the existing FindingsState from storage if it exists, 
     * otherwise sets the storage to default values
     */
    private async loadFromStorage() {
        await this.loadActiveTabFromStorage();
        await this.loadFindingsFromStorage();
        await this.loadFindingsMapFromStorage();
        await this.loadNotificationsFromStorage();
    }

    /**
     * Loads the current active tab from storage.
     */
    private async loadActiveTabFromStorage() {
        const activeTabResults = await chrome.storage.local.get('activeTab')
        if (activeTabResults.activeTab) {
            this.state.activeTab = activeTabResults.activeTab;
        } else {
            await chrome.storage.local.set({ 'activeTab': this.state.activeTab });
        }
    }

    /**
     * Loads the Findings from storage.
     */
    private async loadFindingsFromStorage() {
        const findingsResults = await chrome.storage.local.get(['findings']);
        if (findingsResults.findings) {
            if (!Array.isArray(findingsResults.findings)) {
                this.state.findings = Object.values(findingsResults.findings);
            } else {
                this.state.findings = findingsResults.findings;
            }

            this.state.findings = this.state.findings.map((finding: any) => {
                if (finding.occurrences && !(finding.occurrences instanceof Set)) {
                    const occurrencesArray = Array.isArray(finding.occurrences)
                        ? finding.occurrences
                        : Object.values(finding.occurrences);
                    finding.occurrences = new Set(occurrencesArray);
                }
                return finding;
            });
        } else {
            await chrome.storage.local.set({ 'findings': [] });
        }
    }

    /**
     * Loads the findingsMap from storage.
     */
    private async loadFindingsMapFromStorage() {
        const findingsMapResults = await chrome.storage.local.get(['findingsMap']);
        if (findingsMapResults.findingsMap) {
            if (!Array.isArray(findingsMapResults.findingsMap)) {
                this.state.findingsMap = Object.values(findingsMapResults.findingsMap);
            } else {
                this.state.findingsMap = findingsMapResults.findingsMap;
            }
            this.state.findingsMap = this.state.findingsMap.map((dict: any) => {
                const result: FindingDict = {};

                Object.keys(dict).forEach(key => {
                    const occurrences = dict[key];
                    if (occurrences && !(occurrences instanceof Set)) {
                        result[key] = new Set(Array.isArray(occurrences) ? occurrences : Object.values(occurrences));
                    } else {
                        result[key] = occurrences;
                    }
                });

                return result;
            });
        } else {
            await chrome.storage.local.set({ 'findingsMap': [] });
        }
    }

    /**
     * Loads the current notifications from storage.
     */
    private async loadNotificationsFromStorage() {
        const notificationsResults = await chrome.storage.local.get('notifications');
        if (notificationsResults.notifications) {
            this.state.notifications = notificationsResults.notifications;
        } else {
            await chrome.storage.local.set({ 'notifications': this.state.notifications });
        }
    }

    /**
     * Write the current FindingsState to storage.
     */
    private async saveToStorage() {
        if (!Array.isArray(this.state.findings)) {
            this.state.findings = Object.values(this.state.findings);
        }

        if (!Array.isArray(this.state.findingsMap)) {
            this.state.findingsMap = Object.values(this.state.findingsMap);
        }

        const serializedFindings = this.state.findings.map((finding: any) => ({
            ...finding,
            occurrences: Array.from(finding.occurrences || [])
        }));

        const serializedFindingsMap = this.state.findingsMap.map((dict: any) => {
            const serializedDict: Record<string, any> = {};

            Object.keys(dict).forEach(key => {
                serializedDict[key] = Array.from(dict[key] || []);
            });

            return serializedDict;
        });

        await chrome.storage.local.set({
            'activeTab': this.state.activeTab,
            'findings': serializedFindings,
            'findingsMap': serializedFindingsMap,
            'notifications': this.state.notifications,
        });
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

    /**
     * Adds a new finding if it doesn't aleady exist.
     * @param newFinding - The new finding to add.
     * @returns True if the finding doesn't exist and was added successfuly, false otherwise
     */
    addFinding(newFinding: Finding): boolean {
        if (this.hasFinding(newFinding.fingerprint)) {
            return false;
        } else {
            this.state.findings.push(newFinding);
            this.saveToStorage();
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
            const findingsIdx = this.state.findings.findIndex(obj => obj.fingerprint === fingerprint);
            const findingsMapIdx = this.state.findingsMap.findIndex(obj => fingerprint in obj);
            if (findingsIdx > -1 && findingsMapIdx > -1) {
                this.state.findings.splice(findingsIdx, 1);
                this.state.findingsMap.splice(findingsMapIdx, 1);
                this.saveToStorage();
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
        const idx = this.state.findings.findIndex(obj => obj.fingerprint === fingerprint);
        if (idx > -1) {
            return this.state.findings[idx]
        } else {
            return null;
        }
    }

    /**
     * 
     * @returns All of the findings
     */
    getAllFindings(): Finding[] {
        return this.state.findings;
    }

    /**
     * Checks if a Finding exists for the provided secret fingerprint.
     * @param fingerprint - The secret fingerprint to check for
     * @returns True if the fingerprint has an associated Finding object, false otherwise
     */
    hasFinding(fingerprint: string): boolean {
        return this.state.findingsMap.some(findingDict => fingerprint in findingDict);
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
        this.saveToStorage();
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
        this.state.findings.push(newFinding);
        const newFindingDict: FindingDict = {}
        newFindingDict[newFinding.fingerprint] = newFinding.occurrences;
        this.state.findingsMap.push(newFindingDict);
        this.saveToStorage();
        return newFinding;
    }

    /**
     * Gets the current FindingsState.
     * @returns The FindingsState.
     */
    getState(): FindingsState {
        return { ...this.state };
    }

    /**
     * Updates the current FindingsState given a new state.
     * @param newState The new FindingsState to use to update.
     */
    updateState(newState: FindingsState): void {
        this.state = newState;
        this.saveToStorage();
    }
}