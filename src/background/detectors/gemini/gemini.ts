import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { GeminiOccurrence, GeminiSecretValue } from '../../../types/gemini';
import { validateGeminiCredentials } from '../../../utils/validators/gemini/gemini';
import { GEMINI_RESOURCE_TYPES } from '../../../config/detectors/gemini/gemini';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

export async function detectGeminiKeys(content: string, url: string): Promise<Occurrence[]> {
    const geminiKeyMatches = content.match(patterns['Gemini API Key'].pattern) || [];
    const geminiSecretMatches = content.match(patterns['Gemini API Secret'].pattern) || [];

    if (geminiKeyMatches.length === 0 || geminiSecretMatches.length === 0) {
        return [];
    }

    // Deduplicate matches first
    const uniqueKeys = [...new Set(geminiKeyMatches)];
    const uniqueSecrets = [...new Set(geminiSecretMatches)];

    const existingFindings = await getExistingFindings();
    const validOccurrences: Occurrence[] = [];

    // Try all combinations of keys and secrets
    for (const apiKey of uniqueKeys) {
        for (const apiSecret of uniqueSecrets) {
            // Check if this combination already exists
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    return Object.values(finding.secretValue).some(
                        (match) => {
                            const geminiMatch = match as GeminiSecretValue;
                            return geminiMatch.match.api_key === apiKey && geminiMatch.match.api_secret === apiSecret;
                        }
                    );
                }
            );

            if (alreadyFound) {
                continue;
            }

            const validationResult = await validateGeminiCredentials(apiKey, apiSecret);
            if (validationResult.valid) {
                var newSourceContent: SourceContent = {
                    content: JSON.stringify({
                        api_key: apiKey,
                        api_secret: apiSecret
                    }),
                    contentFilename: url.split('/').pop() || "",
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                }

                try {
                    const sourceMapUrl = getSourceMapUrl(url, content);
                    if (sourceMapUrl) {
                        const sourceMapResponse = await fetch(sourceMapUrl.toString());
                        if (sourceMapResponse.ok) {
                            const sourceMapContent = await sourceMapResponse.text();
                            const consumer = await new sourceMap.SourceMapConsumer(sourceMapContent, null);

                            const keyPosition = findSecretPosition(content, apiKey);
                            const secretPosition = findSecretPosition(content, apiSecret);

                            if (keyPosition.line !== -1 && secretPosition.line !== -1) {
                                const originalKeyPos = consumer.originalPositionFor({
                                    line: keyPosition.line,
                                    column: keyPosition.column
                                });

                                const originalSecretPos = consumer.originalPositionFor({
                                    line: secretPosition.line,
                                    column: secretPosition.column
                                });

                                if (originalKeyPos.source && originalSecretPos.source) {
                                    const sourceContent = consumer.sourceContentFor(originalKeyPos.source);
                                    if (sourceContent) {
                                        const lines = sourceContent.split('\n');
                                        const startLine = Math.max(0, Math.min(originalKeyPos.line, originalSecretPos.line) - 10);
                                        const endLine = Math.min(lines.length - 1, Math.max(originalKeyPos.line, originalSecretPos.line) + 10);

                                        newSourceContent = {
                                            content: lines.slice(startLine, endLine + 1).join('\n'),
                                            contentFilename: originalKeyPos.source.split('/').pop() || "",
                                            contentStartLineNum: startLine,
                                            contentEndLineNum: endLine,
                                            exactMatchNumbers: [originalKeyPos.line - 1, originalSecretPos.line - 1]
                                        };
                                    }
                                }
                            }
                            consumer.destroy();
                        }
                    }
                } catch (error) {
                    // Fall back to bundled content if source map processing fails
                }

                const secretValue: GeminiSecretValue = {
                    match: {
                        api_key: apiKey,
                        api_secret: apiSecret
                    }
                };

                const fingerprint = await computeFingerprint(secretValue.match);

                const geminiOccurrence: GeminiOccurrence = {
                    filePath: url,
                    fingerprint: fingerprint,
                    type: GEMINI_RESOURCE_TYPES.API_KEY,
                    secretType: "Gemini",
                    secretValue: secretValue,
                    sourceContent: newSourceContent,
                    url: url
                };

                validOccurrences.push(geminiOccurrence);
            }
        }
    }

    return validOccurrences;
}