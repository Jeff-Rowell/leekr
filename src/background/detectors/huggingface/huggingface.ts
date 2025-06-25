import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { HuggingFaceOccurrence, HuggingFaceSecretValue } from '../../../types/huggingface';
import { validateHuggingFaceCredentials } from '../../../utils/validators/huggingface/huggingface';
import { HUGGINGFACE_RESOURCE_TYPES } from '../../../config/detectors/huggingface/huggingface';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

export async function detectHuggingFaceKeys(content: string, url: string): Promise<Occurrence[]> {
    const huggingfaceKeyMatches = content.match(patterns['Hugging Face API Key'].pattern) || [];

    if (huggingfaceKeyMatches.length === 0) {
        return [];
    }

    // Deduplicate matches first
    const uniqueKeys = [...new Set(huggingfaceKeyMatches)];

    const existingFindings = await getExistingFindings();
    const validOccurrences: Occurrence[] = [];

    // Process each unique key
    for (const apiKey of uniqueKeys) {
        // Check if this key already exists
        const alreadyFound = existingFindings.some(
            (finding: Finding) => {
                return Object.values(finding.secretValue).some(
                    (match) => {
                        const huggingfaceMatch = match as HuggingFaceSecretValue;
                        return huggingfaceMatch.match?.api_key === apiKey;
                    }
                );
            }
        );

        if (alreadyFound) {
            continue;
        }

        const validationResult = await validateHuggingFaceCredentials(apiKey);
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
            }

            const secretValue: HuggingFaceSecretValue = {
                match: {
                    api_key: apiKey
                }
            };

            const fingerprint = await computeFingerprint(secretValue.match);

            const huggingfaceOccurrence: HuggingFaceOccurrence = {
                filePath: url,
                fingerprint: fingerprint,
                type: HUGGINGFACE_RESOURCE_TYPES.API_KEY,
                secretType: "Hugging Face",
                secretValue: secretValue,
                sourceContent: newSourceContent,
                url: url
            };

            validOccurrences.push(huggingfaceOccurrence);
        }
    }

    return validOccurrences;
}