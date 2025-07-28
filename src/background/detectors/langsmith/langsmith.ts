import * as sourceMap from '../../../../external/source-map';
import { LANGSMITH_RESOURCE_TYPES } from '../../../config/detectors/langsmith/langsmith';
import { patterns } from '../../../config/patterns';
import { LangsmithOccurrence, LangsmithSecretValue } from '../../../types/langsmith';
import { Finding, Occurrence, SourceContent } from '../../../types/findings.types';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { validateLangsmithCredentials } from '../../../utils/validators/langsmith/langsmith';

export async function detectLangsmith(content: string, url: string): Promise<Occurrence[]> {
    const matches = content.match(patterns['LangSmith API Key'].pattern) || [];
    
    if (matches.length === 0) {
        return [];
    }

    const validMatches = matches.filter(match => {
        const singleMatchPattern = new RegExp(patterns['LangSmith API Key'].pattern.source);
        const result = match.match(singleMatchPattern);
        if (!result) return false;
        
        const apiKey = result[1];
        const entropy = calculateShannonEntropy(apiKey);
        const entropyThreshold = patterns['LangSmith API Key'].entropy;
        if (entropy < entropyThreshold) return false;

        const [isFP] = isKnownFalsePositive(apiKey);
        return !isFP;
    });

    if (validMatches.length === 0) {
        return [];
    }

    const existingFindings = await getExistingFindings();
    const filteredMatches = await Promise.all(
        validMatches.map(async (match) => {
            const singleMatchPattern = new RegExp(patterns['LangSmith API Key'].pattern.source);
            const result = match.match(singleMatchPattern);
            if (!result) return null;
            
            const apiKey = result[1];
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    return Object.values(finding.secretValue).some(
                        (secretMatch: LangsmithSecretValue) => {
                            return Object.values(secretMatch).includes(apiKey);
                        }
                    );
                }
            );
            return alreadyFound ? null : apiKey;
        })
    );
    const prunedMatches = filteredMatches.filter((key): key is string => key !== null);

    const validOccurrences: Occurrence[] = [];
    for (const apiKey of prunedMatches) {
        const validationResult = await validateLangsmithCredentials(apiKey);
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
                    const position = findSecretPosition(content, apiKey);
                    const originalPosition = consumer.originalPositionFor({
                        line: position.line,
                        column: position.column
                    });
                    if (originalPosition.source) {
                        const sourceContent = consumer.sourceContentFor(originalPosition.source);
                        newSourceContent = {
                            content: sourceContent,
                            contentFilename: originalPosition.source,
                            contentStartLineNum: originalPosition.line - 5,
                            contentEndLineNum: originalPosition.line + 5,
                            exactMatchNumbers: [originalPosition.line]
                        };
                    }
                });
            }
            
            const resourceType = apiKey.startsWith('lsv2_pt_') ? 
                LANGSMITH_RESOURCE_TYPES['lsv2_pt'] : 
                LANGSMITH_RESOURCE_TYPES['lsv2_sk'];
            
            const match: LangsmithOccurrence = {
                secretType: patterns['LangSmith API Key'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        api_key: apiKey
                    }
                },
                filePath: url.split('/').pop() || "",
                url: url,
                type: resourceType,
                sourceContent: newSourceContent
            };
            match.validity = "valid";
            match.fingerprint = await computeFingerprint(match.secretValue, 'SHA-512');
            validOccurrences.push(match);
        }
    }

    return validOccurrences;
}