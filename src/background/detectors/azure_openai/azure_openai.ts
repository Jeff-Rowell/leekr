import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { AzureOpenAIOccurrence, AzureOpenAISecretValue } from '../../../types/azure_openai';
import { validateAzureOpenAICredentials } from '../../../utils/validators/azure_openai/azure_openai';
import { AZURE_OPENAI_RESOURCE_TYPES } from '../../../config/detectors/azure_openai/azure_openai';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

export async function detectAzureOpenAIKeys(content: string, url: string): Promise<Occurrence[]> {
    const azureOpenAIKeyMatches = content.match(patterns['Azure OpenAI API Key'].pattern) || [];
    const azureOpenAIUrlMatches = content.match(patterns['Azure OpenAI URL'].pattern) || [];

    if (azureOpenAIKeyMatches.length === 0) {
        return [];
    }

    const uniqueKeys = [...new Set(azureOpenAIKeyMatches)];
    const uniqueUrls = [...new Set(azureOpenAIUrlMatches)];

    const existingFindings = await getExistingFindings();

    const filteredAzureOpenAIKeys = await Promise.all(
        uniqueKeys.map(async (apiKey) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    if (finding.secretType === 'Azure OpenAI') {
                        const azureOpenAIMatch = finding.secretValue as AzureOpenAISecretValue;
                        return azureOpenAIMatch && azureOpenAIMatch.match && azureOpenAIMatch.match.api_key === apiKey;
                    }
                    return false;
                }
            );
            return alreadyFound ? null : apiKey;
        })
    );

    const prunedAzureOpenAIKeys = filteredAzureOpenAIKeys.filter((key): key is string => key !== null);
    const validOccurrences: Occurrence[] = [];

    for (const apiKey of prunedAzureOpenAIKeys) {
        const urlsToTry = uniqueUrls.length > 0 ? uniqueUrls : [undefined];
        
        for (const azureOpenAIUrl of urlsToTry) {
            const validationResult = await validateAzureOpenAICredentials(apiKey, azureOpenAIUrl);
            
            if (validationResult.valid) {
                var newSourceContent: SourceContent = {
                    content: JSON.stringify({
                        api_key: apiKey,
                        url: azureOpenAIUrl
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
                        
                        let exactMatchNumbers: number[] = [];
                        let minLine = originalKeyPos.line;
                        let maxLine = originalKeyPos.line;
                        
                        if (originalKeyPos.source) {
                            exactMatchNumbers.push(originalKeyPos.line);
                            
                            if (azureOpenAIUrl) {
                                const urlPosition = findSecretPosition(content, azureOpenAIUrl);
                                const originalUrlPos = consumer.originalPositionFor({
                                    line: urlPosition.line,
                                    column: urlPosition.column
                                });
                                
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

                const secretValue: AzureOpenAISecretValue = {
                    match: {
                        api_key: apiKey,
                        url: azureOpenAIUrl
                    }
                };

                const fingerprint = await computeFingerprint(secretValue.match);

                const azureOpenAIOccurrence: AzureOpenAIOccurrence = {
                    filePath: url,
                    fingerprint: fingerprint,
                    type: AZURE_OPENAI_RESOURCE_TYPES.API_KEY,
                    secretType: "Azure OpenAI",
                    secretValue: secretValue,
                    sourceContent: newSourceContent,
                    url: url
                };

                validOccurrences.push(azureOpenAIOccurrence);
            }
        }
    }

    return validOccurrences;
}