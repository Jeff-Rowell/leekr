import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { ArtifactoryOccurrence, ArtifactorySecretValue } from '../../../types/artifactory';
import { validateArtifactoryCredentials } from '../../../utils/validators/artifactory/artifactory';
import { ARTIFACTORY_RESOURCE_TYPES } from '../../../config/detectors/artifactory/artifactory';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

export async function detectArtifactoryKeys(content: string, url: string): Promise<Occurrence[]> {
    const artifactoryKeyMatches = content.match(patterns['Artifactory Access Token'].pattern) || [];
    const artifactoryUrlMatches = content.match(patterns['Artifactory URL'].pattern) || [];

    if (artifactoryKeyMatches.length === 0) {
        return [];
    }

    // Deduplicate matches first
    const uniqueKeys = [...new Set(artifactoryKeyMatches)];
    const uniqueUrls = [...new Set(artifactoryUrlMatches)];

    const existingFindings = await getExistingFindings();
    const validOccurrences: Occurrence[] = [];

    // Process each unique key
    for (const apiKey of uniqueKeys) {
        // Check if this key already exists
        const alreadyFound = existingFindings.some(
            (finding: Finding) => {
                return Object.values(finding.secretValue).some(
                    (match) => {
                        const artifactoryMatch = match as ArtifactorySecretValue;
                        return artifactoryMatch.match?.api_key === apiKey;
                    }
                );
            }
        );

        if (alreadyFound) {
            continue;
        }

        // Try validation with each found URL, or without URL if none found
        const urlsToTry = uniqueUrls.length > 0 ? uniqueUrls : [undefined];
        
        for (const artifactoryUrl of urlsToTry) {
            const validationResult = await validateArtifactoryCredentials(apiKey, artifactoryUrl);
            
            if (validationResult.valid) {
                var newSourceContent: SourceContent = {
                    content: JSON.stringify({
                        api_key: apiKey,
                        url: artifactoryUrl
                    }),
                    contentFilename: url.split('/').pop() || "",
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                }

                const sourceMapUrl = getSourceMapUrl(url, content);
                if (sourceMapUrl) {
                    const sourceMapResponse = await fetch(sourceMapUrl);
                    const sourceMapContent = await sourceMapResponse.text();
                    sourceMap.SourceMapConsumer.initialize({
                        "lib/mappings.wasm": chrome.runtime.getURL('libs/mappings.wasm'),
                    });
                    await sourceMap.SourceMapConsumer.with(sourceMapContent, null, (consumer: any) => {
                        const keyPosition = findSecretPosition(content, apiKey);
                        const originalKeyPos = consumer.originalPositionFor({
                            line: keyPosition.line,
                            column: keyPosition.column
                        });
                        
                        let exactMatchNumbers: number[] = [];
                        let minLine = originalKeyPos.line;
                        let maxLine = originalKeyPos.line;
                        
                        if (originalKeyPos.source) {
                            exactMatchNumbers.push(originalKeyPos.line);
                            
                            // If we have a URL, also find its position
                            if (artifactoryUrl) {
                                const urlPosition = findSecretPosition(content, artifactoryUrl);
                                const originalUrlPos = consumer.originalPositionFor({
                                    line: urlPosition.line,
                                    column: urlPosition.column
                                });
                                
                                // Only include URL position if it's in the same source file
                                if (originalUrlPos.source === originalKeyPos.source) {
                                    exactMatchNumbers.push(originalUrlPos.line);
                                    minLine = Math.min(minLine, originalUrlPos.line);
                                    maxLine = Math.max(maxLine, originalUrlPos.line);
                                }
                            }
                            
                            const sourceContent = consumer.sourceContentFor(originalKeyPos.source);
                            newSourceContent = {
                                content: sourceContent,
                                contentFilename: originalKeyPos.source,
                                contentStartLineNum: minLine - 5,
                                contentEndLineNum: maxLine + 5,
                                exactMatchNumbers: exactMatchNumbers
                            };
                        }
                    });
                }

                const secretValue: ArtifactorySecretValue = {
                    match: {
                        api_key: apiKey,
                        url: artifactoryUrl
                    }
                };

                const fingerprint = await computeFingerprint(secretValue.match);

                const artifactoryOccurrence: ArtifactoryOccurrence = {
                    filePath: url,
                    fingerprint: fingerprint,
                    type: ARTIFACTORY_RESOURCE_TYPES.ACCESS_TOKEN,
                    secretType: "Artifactory",
                    secretValue: secretValue,
                    sourceContent: newSourceContent,
                    url: url
                };

                validOccurrences.push(artifactoryOccurrence);
                break; // Stop trying other URLs once we find a valid combination
            }
        }
    }

    return validOccurrences;
}