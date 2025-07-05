import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "../../../types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { JotFormOccurrence } from '../../../types/jotform';
import { validateJotFormCredentials } from '../../../utils/validators/jotform/jotform';
import { JOTFORM_RESOURCE_TYPES, DEFAULT_JOTFORM_CONFIG } from '../../../config/detectors/jotform/jotform';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';
import * as sourceMap from '../../../../external/source-map';

export async function detectJotFormKeys(content: string, url: string): Promise<Occurrence[]> {
    const jotformPattern = patterns['JotForm API Key'].pattern;
    const regex = new RegExp(jotformPattern.source, jotformPattern.flags);
    
    const matches = Array.from(content.matchAll(regex));
    
    if (matches.length === 0) {
        return [];
    }

    const results: Occurrence[] = [];
    
    for (const match of matches) {
        if (!match[1]) {
            continue;
        }

        const apiKey = match[1].trim();
        
        if (!apiKey || apiKey.length !== 32) {
            continue;
        }

        const entropy = calculateShannonEntropy(apiKey);
        if (entropy < DEFAULT_JOTFORM_CONFIG.requiredEntropy) {
            continue;
        }

        // Check for programming naming convention patterns to avoid false positives
        if (isProgrammingPattern(apiKey)) {
            continue;
        }

        const existingFindings = await getExistingFindings();
        
        const alreadyFound = existingFindings.some(
            (finding: Finding) => {
                if (finding.secretType !== 'JotForm') {
                    return false;
                }
                return Object.values(finding.secretValue).some(
                    (match) => {
                        const jotformMatch = match as any;
                        return jotformMatch.apiKey === apiKey ||
                               (jotformMatch.match && jotformMatch.match.apiKey === apiKey);
                    }
                );
            }
        );

        if (alreadyFound) {
            continue;
        }

        const validationResult = await validateJotFormCredentials(apiKey);
        
        if (!validationResult.valid) {
            continue;
        }

        const sourceContent: SourceContent = {
            content: apiKey,
            contentFilename: url.split('/').pop() || "",
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        };

        const sourceMapUrl = getSourceMapUrl(url, content);
        if (sourceMapUrl) {
            try {
                const sourceMapResponse = await fetch(sourceMapUrl);
                const sourceMapContent = await sourceMapResponse.text();
                sourceMap.SourceMapConsumer.initialize({
                    "lib/mappings.wasm": chrome.runtime.getURL('libs/mappings.wasm'),
                });
                await sourceMap.SourceMapConsumer.with(sourceMapContent, null, (consumer: any) => {
                    const position = findSecretPosition(content, match[0]);
                    const originalPosition = consumer.originalPositionFor({
                        line: position.line,
                        column: position.column
                    });
                    if (originalPosition.source && originalPosition.line) {
                        const originalSource = consumer.sourceContentFor(originalPosition.source);
                        if (originalSource) {
                            const apiKeyLength = apiKey.length;
                            const startLine = originalPosition.line;
                            const endLine = startLine;
                            
                            sourceContent.content = originalSource;
                            sourceContent.contentFilename = originalPosition.source;
                            sourceContent.contentStartLineNum = Math.max(1, startLine - 5);
                            sourceContent.contentEndLineNum = endLine + 5;
                            sourceContent.exactMatchNumbers = [startLine];
                        }
                    }
                });
            } catch (error) {
                // Continue with default source content
            }
        }

        const occurrence: JotFormOccurrence = {
            secretType: patterns['JotForm API Key'].familyName,
            fingerprint: "",
            secretValue: {
                match: {
                    apiKey: apiKey
                }
            },
            filePath: url.split('/').pop() || "",
            url: url,
            type: JOTFORM_RESOURCE_TYPES['API_KEY'],
            sourceContent: sourceContent,
            validity: "valid"
        };

        occurrence.fingerprint = await computeFingerprint(occurrence.secretValue, 'SHA-512');
        
        results.push(occurrence);
    }
    
    return results;
}