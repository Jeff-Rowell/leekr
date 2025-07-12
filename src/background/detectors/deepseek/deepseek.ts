import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from '../../../types/findings.types';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { DeepSeekOccurrence, DeepSeekSecretValue } from '../../../types/deepseek';
import { validateDeepSeekApiKey } from '../../../utils/validators/deepseek/deepseek';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

export async function detectDeepSeekKeys(content: string, url: string): Promise<Occurrence[]> {
    console.log('🔍 DeepSeek Detector: Starting detection for URL:', url);
    const deepSeekKeyMatches = content.match(patterns['DeepSeek API Key'].pattern) || [];
    console.log('📊 DeepSeek Detector: Found', deepSeekKeyMatches.length, 'potential matches');

    if (deepSeekKeyMatches.length === 0) {
        console.log('❌ DeepSeek Detector: No matches found, returning empty array');
        return [];
    }

    // Deduplicate matches first
    const uniqueKeys = [...new Set(deepSeekKeyMatches)];
    console.log('🔄 DeepSeek Detector: After deduplication, processing', uniqueKeys.length, 'unique keys');

    const existingFindings = await getExistingFindings();
    console.log('📋 DeepSeek Detector: Found', existingFindings.length, 'existing findings to check against');
    const validOccurrences: Occurrence[] = [];

    // Process each unique key
    for (const apiKey of uniqueKeys) {
        console.log('🔑 DeepSeek Detector: Processing API key:', apiKey.substring(0, 10) + '...');
        
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
            console.log('⚠️ DeepSeek Detector: Key already exists in findings, skipping');
            continue;
        }

        // Validate the API key
        console.log('🔍 DeepSeek Detector: Validating API key...');
        const validationResult = await validateDeepSeekApiKey(apiKey);
        console.log('📊 DeepSeek Detector: Validation result:', validationResult.valid, validationResult.error || '');
        
        if (validationResult.valid) {
            console.log('✅ DeepSeek Detector: API key is valid, creating occurrence');
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
                console.log('🗺️ DeepSeek Detector: Processing source map:', sourceMapUrl.toString());
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
                            console.log('📍 DeepSeek Detector: Mapped to original source:', originalKeyPos.source, 'line:', originalKeyPos.line);
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
            console.log('🔒 DeepSeek Detector: Generated fingerprint:', fingerprint);

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
            console.log('✅ DeepSeek Detector: Added valid occurrence, total so far:', validOccurrences.length);
        } else {
            console.log('❌ DeepSeek Detector: API key validation failed, skipping');
        }
    }

    console.log('🏁 DeepSeek Detector: Detection complete, returning', validOccurrences.length, 'valid occurrences');
    return validOccurrences;
}