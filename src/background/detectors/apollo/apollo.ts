import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { ApolloOccurrence, ApolloSecretValue } from '../../../types/apollo';
import { validateApolloCredentials } from '../../../utils/validators/apollo/apollo';
import { APOLLO_RESOURCE_TYPES, DEFAULT_APOLLO_API_KEY_CONFIG } from '../../../config/detectors/apollo/apollo';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';

export async function detectApolloKeys(content: string, url: string): Promise<Occurrence[]> {
    const apolloPattern = patterns['Apollo API Key'].pattern;
    const apolloKeyMatches: string[] = [];
    
    let match;
    while ((match = apolloPattern.exec(content)) !== null) {
        if (match[1]) { // match[1] is the captured group (the 22-char key)
            apolloKeyMatches.push(match[1]);
        }
    }

    if (apolloKeyMatches.length === 0) {
        return [];
    }

    // Filter keys by entropy and programming naming patterns to avoid false positives
    const validApolloKeys = apolloKeyMatches.filter(key => {
        const entropy = calculateShannonEntropy(key);
        const apolloKeyEntropyThreshold = patterns["Apollo API Key"].entropy;
        if (entropy < apolloKeyEntropyThreshold) return false;

        // Check for programming naming convention patterns (camelCase, PascalCase, etc.)
        const isProgrammingPattern = DEFAULT_APOLLO_API_KEY_CONFIG.falsePositivePatterns.some(pattern => 
            pattern.test(key)
        );
        if (isProgrammingPattern) return false;

        const [isFP] = isKnownFalsePositive(key);
        return !isFP;
    });

    if (validApolloKeys.length === 0) {
        return [];
    }

    const uniqueKeys = [...new Set(validApolloKeys)];

    const existingFindings = await getExistingFindings();

    const filteredApolloKeys = await Promise.all(
        uniqueKeys.map(async (apiKey) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    if (finding.secretType === 'Apollo') {
                        return Object.values(finding.secretValue).some(
                            (match) => {
                                return Object.values(match as ApolloSecretValue).includes(apiKey);
                            }
                        );
                    }
                    return false;
                }
            );
            return alreadyFound ? null : apiKey;
        })
    );

    const prunedApolloKeys = filteredApolloKeys.filter((key): key is string => key !== null);
    const validOccurrences: Occurrence[] = [];

    for (const apiKey of prunedApolloKeys) {
        const validationResult = await validateApolloCredentials(apiKey);
        
        if (validationResult.valid) {
            var newSourceContent: SourceContent = {
                content: JSON.stringify({
                    api_key: apiKey
                }),
                contentFilename: url.split('/').pop() || "",
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            }

            const sourceMapUrl = getSourceMapUrl(url, content);
            if (sourceMapUrl) {
                const sourceMapResponse = await fetch(sourceMapUrl.toString());
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
                    
                    if (originalKeyPos.source) {
                        const sourceContent = consumer.sourceContentFor(originalKeyPos.source);
                        newSourceContent = {
                            content: sourceContent,
                            contentFilename: originalKeyPos.source,
                            contentStartLineNum: originalKeyPos.line - 5,
                            contentEndLineNum: originalKeyPos.line + 5,
                            exactMatchNumbers: [originalKeyPos.line]
                        };
                    }
                });
            }

            const secretValue: ApolloSecretValue = {
                match: {
                    api_key: apiKey
                }
            };

            const fingerprint = await computeFingerprint(secretValue.match);

            const apolloOccurrence: ApolloOccurrence = {
                filePath: url,
                fingerprint: fingerprint,
                type: APOLLO_RESOURCE_TYPES.API_KEY,
                secretType: "Apollo",
                secretValue: secretValue,
                sourceContent: newSourceContent,
                url: url
            };

            validOccurrences.push(apolloOccurrence);
        }
    }

    return validOccurrences;
}