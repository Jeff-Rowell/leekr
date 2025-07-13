import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from '../../../types/findings.types';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { DeepSeekOccurrence, DeepSeekSecretValue } from '../../../types/deepseek';
import { validateDeepSeekApiKey } from '../../../utils/validators/deepseek/deepseek';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

export async function detectDeepSeekKeys(content: string, url: string): Promise<Occurrence[]> {
    const deepSeekKeyMatches = content.match(patterns['DeepSeek API Key'].pattern) || [];

    if (deepSeekKeyMatches.length === 0) {
        return [];
    }

    // Deduplicate matches first
    const uniqueKeys = [...new Set(deepSeekKeyMatches)];

    const existingFindings = await getExistingFindings();
    const validOccurrences: Occurrence[] = [];

    // Process each unique key
    for (const apiKey of uniqueKeys) {
        // Check if this key already exists
        const alreadyFound = existingFindings.some(
            (finding: Finding) => {
                return Object.values(finding.secretValue).some(
                    (match) => {
                        const deepSeekMatch = match as DeepSeekSecretValue;
                        return deepSeekMatch.match && deepSeekMatch.match.apiKey === apiKey;
                    }
                );
            }
        );

        if (alreadyFound) {
            continue;
        }

        // Validate the API key
        const validationResult = await validateDeepSeekApiKey(apiKey);
        
        if (validationResult.valid) {
            var newSourceContent: SourceContent = {
                content: JSON.stringify({
                    apiKey: apiKey
                }),
                contentFilename: url.split('/').pop() || "",
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            }

            const sourceMapUrl = getSourceMapUrl(url, content);
            if (sourceMapUrl) {
                try {
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
                } catch (error) {
                    console.warn('Failed to process source map for DeepSeek detection:', error);
                }
            }

            const secretValue: DeepSeekSecretValue = {
                match: {
                    apiKey: apiKey
                }
            };

            const fingerprint = await computeFingerprint(secretValue.match);

            const deepSeekOccurrence: DeepSeekOccurrence = {
                filePath: url,
                fingerprint: fingerprint,
                type: "API Key",
                secretType: "DeepSeek",
                secretValue: secretValue,
                sourceContent: newSourceContent,
                url: url
            };

            validOccurrences.push(deepSeekOccurrence);
        }
    }

    return validOccurrences;
}