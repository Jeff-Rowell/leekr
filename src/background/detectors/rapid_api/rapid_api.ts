import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { RapidApiOccurrence, RapidApiSecretValue } from '../../../types/rapid_api';
import { validateRapidApiCredentials } from '../../../utils/validators/rapid_api/rapid_api';
import { RAPID_API_RESOURCE_TYPES } from '../../../config/detectors/rapid_api/rapid_api';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';

export async function detectRapidApiKeys(content: string, url: string): Promise<Occurrence[]> {
    const rapidApiKeyMatches = content.match(patterns['RapidAPI Key'].pattern) || [];

    if (rapidApiKeyMatches.length === 0) {
        return [];
    }

    const uniqueKeys = [...new Set(rapidApiKeyMatches)];

    const validKeys = uniqueKeys.filter(key => {
        const entropy = calculateShannonEntropy(key);
        const entropyThreshold = patterns['RapidAPI Key'].entropy;
        if (entropy < entropyThreshold) return false;

        if (isProgrammingPattern(key)) return false;

        return true;
    });

    const existingFindings = await getExistingFindings();
    const filteredRapidApiKeys = await Promise.all(
        validKeys.map(async (apiKey) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    return Object.values(finding.secretValue).some(
                        (match) => {
                            return Object.values(match as RapidApiSecretValue).includes(apiKey);
                        }
                    );
                }
            );
            return alreadyFound ? null : apiKey;
        })
    );

    const prunedRapidApiKeys = filteredRapidApiKeys.filter((key): key is string => key !== null);
    const validOccurrences: Occurrence[] = [];

    for (const apiKey of prunedRapidApiKeys) {
        const validationResult = await validateRapidApiCredentials(apiKey);
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
            const match: RapidApiOccurrence = {
                secretType: patterns['RapidAPI Key'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        api_key: apiKey,
                    }
                },
                filePath: url.split('/').pop() || "",
                url: url,
                type: RAPID_API_RESOURCE_TYPES[validationResult.type],
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