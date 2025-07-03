import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { GcpOccurrence, GcpCredentials } from '../../../types/gcp';
import { validateGcpCredentials } from '../../../utils/validators/gcp/gcp';
import { GCP_RESOURCE_TYPES } from '../../../config/detectors/gcp/gcp';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';

interface GcpComponents {
    type?: string;
    project_id?: string;
    private_key_id?: string;
    private_key?: string;
    client_email?: string;
    client_id?: string;
    auth_uri?: string;
    token_uri?: string;
    auth_provider_x509_cert_url?: string;
    client_x509_cert_url?: string;
    universe_domain?: string;
}

export async function detectGcpKeys(content: string, url: string): Promise<Occurrence[]> {
    if (!patterns['GCP Service Account Key'].pattern.test(content)) {
        return [];
    }

    const gcpComponents = extractGcpComponents(content);
    
    if (!hasAllRequiredComponents(gcpComponents)) {
        return [];
    }

    const credentials: GcpCredentials = {
        type: gcpComponents.type!,
        project_id: gcpComponents.project_id!,
        private_key_id: gcpComponents.private_key_id!,
        private_key: gcpComponents.private_key!.replace(/\\n/g, '\n'),
        client_email: gcpComponents.client_email!,
        client_id: gcpComponents.client_id || "",
        auth_uri: gcpComponents.auth_uri || "https://accounts.google.com/o/oauth2/auth",
        token_uri: gcpComponents.token_uri || "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url: gcpComponents.auth_provider_x509_cert_url!,
        client_x509_cert_url: gcpComponents.client_x509_cert_url || ""
    };

    let rawPrivateKey = gcpComponents.private_key!;
    if (!rawPrivateKey.endsWith('\\n') && rawPrivateKey.includes('\\n')) {
        rawPrivateKey = rawPrivateKey + '\\n';
    }
    
    const rawCredentials: GcpCredentials = {
        type: gcpComponents.type!,
        project_id: gcpComponents.project_id!,
        private_key_id: gcpComponents.private_key_id!,
        private_key: rawPrivateKey,
        client_email: gcpComponents.client_email!,
        client_id: gcpComponents.client_id || "",
        auth_uri: gcpComponents.auth_uri || "https://accounts.google.com/o/oauth2/auth",
        token_uri: gcpComponents.token_uri || "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url: gcpComponents.auth_provider_x509_cert_url!,
        client_x509_cert_url: gcpComponents.client_x509_cert_url || ""
    };

    const credentialsJson = JSON.stringify(credentials);
    const rawCredentialsJson = JSON.stringify(rawCredentials);

    const [isFalsePositive] = isKnownFalsePositive(credentialsJson);
    if (isFalsePositive) {
        return [];
    }
    const existingFindings = await getExistingFindings();
    const alreadyFound = existingFindings.some(
        (finding: Finding) => {
            if (finding.secretType !== 'Google Cloud Platform') {
                return false;
            }
            return Object.values(finding.secretValue).some(
                (match) => {
                    const gcpMatch = match as any;
                    return gcpMatch.service_account_key === rawCredentialsJson || 
                           (gcpMatch.match && gcpMatch.match.service_account_key === rawCredentialsJson);
                }
            );
        }
    );

    if (alreadyFound) {
        return [];
    }

    const validationResult = await validateGcpCredentials(credentialsJson);
    if (!validationResult.valid) {
        return [];
    }
    const sourceContent: SourceContent = {
        content: credentialsJson,
        contentFilename: url.split('/').pop() || "",
        contentStartLineNum: -1,
        contentEndLineNum: -1,
        exactMatchNumbers: [-1]
    };

    const sourceMapUrl = getSourceMapUrl(url, content);
    if (sourceMapUrl) {
        try {
            const sourceMapResponse = await fetch(sourceMapUrl);
            const sourceMapContent = await sourceMapResponse.text();
            sourceMap.SourceMapConsumer.initialize({
                "lib/mappings.wasm": chrome.runtime.getURL('libs/mappings.wasm'),
            });
            await sourceMap.SourceMapConsumer.with(sourceMapContent, null, (consumer: any) => {
                // Find positions for all GCP components to highlight the entire JSON object
                const componentPositions: { line: number; column: number }[] = [];
                const originalPositions: number[] = [];
                
                // Find positions for each component that exists in the content
                if (gcpComponents.project_id) {
                    componentPositions.push(findSecretPosition(content, gcpComponents.project_id));
                }
                if (gcpComponents.private_key_id) {
                    componentPositions.push(findSecretPosition(content, gcpComponents.private_key_id));
                }
                if (gcpComponents.private_key) {
                    componentPositions.push(findSecretPosition(content, gcpComponents.private_key));
                }
                if (gcpComponents.client_email) {
                    componentPositions.push(findSecretPosition(content, gcpComponents.client_email));
                }
                if (gcpComponents.client_id) {
                    componentPositions.push(findSecretPosition(content, gcpComponents.client_id));
                }
                if (gcpComponents.auth_provider_x509_cert_url) {
                    componentPositions.push(findSecretPosition(content, gcpComponents.auth_provider_x509_cert_url));
                }
                
                // Map each position to original source location
                for (const position of componentPositions) {
                    const originalPosition = consumer.originalPositionFor({
                        line: position.line,
                        column: position.column
                    });
                    if (originalPosition.source && originalPosition.line) {
                        originalPositions.push(originalPosition.line);
                    }
                }
                
                if (originalPositions.length > 0) {
                    let sourceKey = null;
                    if (originalPositions[0]) {
                        sourceKey = consumer.originalPositionFor({
                            line: componentPositions[0].line,
                            column: componentPositions[0].column
                        }).source;
                    }
                    const originalSource = consumer.sourceContentFor(sourceKey);
                    
                    if (originalSource) {
                        // Calculate min and max line numbers for the entire JSON object
                        const minLine = Math.min(...originalPositions);
                        const maxLine = Math.max(...originalPositions);
                        
                        sourceContent.content = originalSource;
                        sourceContent.contentFilename = consumer.originalPositionFor({
                            line: componentPositions[0].line,
                            column: componentPositions[0].column
                        }).source;
                        sourceContent.contentStartLineNum = minLine - 5;
                        sourceContent.contentEndLineNum = maxLine + 5;
                        sourceContent.exactMatchNumbers = originalPositions;
                    }
                }
            });
        } catch (error) {
            // Continue with default source content if source map processing fails
        }
    }

    const occurrence: GcpOccurrence = {
        secretType: patterns['GCP Service Account Key'].familyName,
        fingerprint: "",
        secretValue: {
            match: {
                service_account_key: credentialsJson,
                type: credentials.type,
                project_id: credentials.project_id,
                private_key_id: credentials.private_key_id,
                client_email: credentials.client_email,
                client_id: credentials.client_id,
                auth_uri: credentials.auth_uri,
                token_uri: credentials.token_uri,
                auth_provider_x509_cert_url: credentials.auth_provider_x509_cert_url,
                client_x509_cert_url: credentials.client_x509_cert_url
            }
        },
        filePath: url.split('/').pop() || "",
        url: url,
        type: GCP_RESOURCE_TYPES[validationResult.type],
        sourceContent: sourceContent,
        validity: "valid"
    };

    occurrence.fingerprint = await computeFingerprint(occurrence.secretValue, 'SHA-512');
    
    return [occurrence];
}

export function extractComponentWithPattern(content: string, patternName: string, fallbackPatternName?: string): string | undefined {
    const contextMatches = Array.from(content.matchAll(patterns[patternName].pattern));
    if (contextMatches.length > 0) {
        // Return first non-null capture group
        for (let i = 1; i < contextMatches[0].length; i++) {
            if (contextMatches[0][i]) {
                return contextMatches[0][i];
            }
        }
    }
    
    if (fallbackPatternName) {
        const fallbackMatches = Array.from(content.matchAll(patterns[fallbackPatternName].pattern));
        if (fallbackMatches.length > 0) {
            return fallbackMatches[0][1];
        }
    }
    
    return undefined;
}

export function extractGcpComponents(content: string): GcpComponents {
    const components: GcpComponents = {};

    if (patterns['GCP Service Account Type'].pattern.test(content) || content.includes('service_account')) {
        components.type = 'service_account';
    }

    components.project_id = extractComponentWithPattern(content, 'GCP Project ID Context', 'GCP Project ID');
    components.private_key_id = extractComponentWithPattern(content, 'GCP Private Key ID Context', 'GCP Private Key ID');
    components.private_key = extractComponentWithPattern(content, 'GCP Private Key Context', 'GCP Private Key');
    components.client_email = extractComponentWithPattern(content, 'GCP Client Email Context', 'GCP Client Email');
    components.client_id = extractComponentWithPattern(content, 'GCP Client ID Context', 'GCP Client ID');
    components.auth_provider_x509_cert_url = extractComponentWithPattern(content, 'GCP Auth Provider Context', 'GCP Auth Provider URL');

    if (patterns['GCP Auth URI'].pattern.test(content)) {
        components.auth_uri = "https://accounts.google.com/o/oauth2/auth";
    }

    if (patterns['GCP Token URI'].pattern.test(content)) {
        components.token_uri = "https://oauth2.googleapis.com/token";
    }

    const clientCertMatch = extractComponentWithPattern(content, 'GCP Client Cert URL');
    if (clientCertMatch) {
        components.client_x509_cert_url = clientCertMatch;
    }

    if (patterns['GCP Universe Domain'].pattern.test(content)) {
        components.universe_domain = "googleapis.com";
    }

    return components;
}

export function hasAllRequiredComponents(components: GcpComponents): boolean {
    return !!(
        components.type &&
        components.project_id &&
        components.private_key_id &&
        components.private_key &&
        components.client_email &&
        components.auth_provider_x509_cert_url
    );
}