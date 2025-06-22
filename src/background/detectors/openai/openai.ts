import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { OpenAIOccurrence, OpenAISecretValue } from '../../../types/openai';
import { validateOpenAICredentials } from '../../../utils/validators/openai/openai';
import { OPENAI_RESOURCE_TYPES } from '../../../config/detectors/openai/openai';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

export async function detectOpenAIKeys(content: string, url: string): Promise<Occurrence[]> {
    const openaiKeyMatches = content.match(patterns['OpenAI API Key'].pattern) || [];

    if (openaiKeyMatches.length === 0) {
        return [];
    }

    // Deduplicate matches first
    const uniqueKeys = [...new Set(openaiKeyMatches)];

    const existingFindings = await getExistingFindings();
    const filteredOpenAIKeys = await Promise.all(
        uniqueKeys.map(async (apiKey) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    return Object.values(finding.secretValue).some(
                        (match) => {
                            return Object.values(match as OpenAISecretValue).includes(apiKey);
                        }
                    );
                }
            );
            return alreadyFound ? null : apiKey;
        })
    );

    const prunedOpenAIKeys = filteredOpenAIKeys.filter((key): key is string => key !== null);
    const validOccurrences: Occurrence[] = [];

    for (const apiKey of prunedOpenAIKeys) {
        const validationResult = await validateOpenAICredentials(apiKey);
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
                    const apiKeyPosition = findSecretPosition(content, apiKey);
                    const apiKeyOriginalPosition = consumer.originalPositionFor({
                        line: apiKeyPosition.line,
                        column: apiKeyPosition.column
                    });
                    if (apiKeyOriginalPosition.source) {
                        const sourceContent = consumer.sourceContentFor(apiKeyOriginalPosition.source);
                        newSourceContent = {
                            content: sourceContent,
                            contentFilename: apiKeyOriginalPosition.source,
                            contentStartLineNum: apiKeyOriginalPosition.line - 5,
                            contentEndLineNum: apiKeyOriginalPosition.line + 5,
                            exactMatchNumbers: [apiKeyOriginalPosition.line]
                        };
                    }
                });
            }
            const match: OpenAIOccurrence = {
                secretType: patterns['OpenAI API Key'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        api_key: apiKey,
                    }
                },
                filePath: url.split('/').pop() || "",
                url: url,
                type: OPENAI_RESOURCE_TYPES[validationResult.type],
                sourceContent: newSourceContent
            };
            match.validity = "valid";
            match.fingerprint = await computeFingerprint(match.secretValue, 'SHA-512');
            validOccurrences.push(match);
        }
    }

    if (validOccurrences.length > 0) {
        return validOccurrences;
    } else {
        return [];
    }
}