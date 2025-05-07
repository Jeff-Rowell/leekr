import { Finding } from "../../types/findings.types";
import { Pattern, PatternsObj } from "../../types/patterns.types";
import { patterns } from "./patterns";

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

export function getSourceMapUrl(bundleUrl: string, bundleContent: string): URL | null {
    // Look for sourceMappingURL comment which is typically at the end of the file
    // Format: //# sourceMappingURL=bundle.js.map
    const sourceMapRegex = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/;
    const match = bundleContent.match(sourceMapRegex);
    if (!match || !match[1]) {
        return null;
    }
    const sourceMapPath = match[1];

    // If the source map URL is already absolute, return it
    if (sourceMapPath.startsWith('http://') || sourceMapPath.startsWith('https://') || sourceMapPath.startsWith('data:')) {
        return new URL(sourceMapPath);
    }
    try {
        const bundleUrlObj = new URL(bundleUrl);

        // If the sourcemap path starts with a slash, it's relative to the origin
        if (sourceMapPath.startsWith('/')) {
            return new URL(`${bundleUrlObj.origin}${sourceMapPath}`);
        }

        // Otherwise, it's relative to the bundle's path
        // Remove the filename from the bundle URL path
        const bundlePath = bundleUrlObj.pathname.substring(0, bundleUrlObj.pathname.lastIndexOf('/') + 1);
        return new URL(`${bundleUrlObj.origin}${bundlePath}${sourceMapPath}`);
    } catch (error) {
        console.error('Error resolving source map URL:', error);
        return null;
    }
}

export function findSecretPosition(bundleContent: string, secret: string): { line: number; column: number } {
    const index = bundleContent.indexOf(secret);

    if (index === -1) {
        return { line: -1, column: -1 };
    }

    let line = 1;
    let column = 1;
    for (let i = 0; i < index; i++) {
        if (bundleContent[i] === '\n') {
            line++;
            column = 1;
        } else {
            column++;
        }
    }

    return { line, column };
}

export function serializePatterns(patterns: PatternsObj): Record<string, Omit<Pattern, 'pattern'> & { pattern: string }> {
    const serialized: Record<string, Omit<Pattern, 'pattern'> & { pattern: string }> = {};
    Object.entries(patterns).forEach(([key, value]) => {
        serialized[key] = {
            ...value,
            pattern: value.pattern.source
        };
    });
    return serialized;
}

export function deserializePatterns(serializedPatterns: Record<string, Omit<Pattern, 'pattern'> & { pattern: string }>): PatternsObj {
    const deserialized: PatternsObj = {};
    Object.entries(serializedPatterns).forEach(([key, value]) => {
        deserialized[key] = {
            ...value,
            pattern: value.global ? new RegExp(value.pattern, "g") : new RegExp(value.pattern)
        };
    });
    return deserialized;
}

export function retrievePatterns(): Promise<PatternsObj> {
    return new Promise((resolve) => {
        chrome.storage.local.get(['patterns'], (result) => {
            if (result.patterns) {
                const deserialized = deserializePatterns(result.patterns);
                resolve(deserialized);
            } else {
                resolve({});
            }
        });
    });
}

export function getExistingPatterns(): Promise<PatternsObj> {
    return new Promise(async (resolve) => {
        const patterns = await retrievePatterns();
        resolve(patterns || {});
    });
}

export function storePatterns(patterns: PatternsObj): Promise<void> {
    const serializedPatterns = serializePatterns(patterns)
    return new Promise((resolve) => {
        chrome.storage.local.set({ patterns: serializedPatterns }, resolve);
    });
}
