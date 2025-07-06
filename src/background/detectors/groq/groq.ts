import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "../../../types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { GroqOccurrence } from '../../../types/groq';
import { validateGroqCredentials } from '../../../utils/validators/groq/groq';
import { GROQ_RESOURCE_TYPES, DEFAULT_GROQ_CONFIG } from '../../../config/detectors/groq/groq';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';
import * as sourceMap from '../../../../external/source-map';

export async function detectGroqKeys(content: string, url: string): Promise<Occurrence[]> {
    const groqPattern = patterns['Groq API Key'].pattern;
    const regex = new RegExp(groqPattern.source, groqPattern.flags);
    
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
        
        if (!apiKey || apiKey.length !== 56) {
            continue;
        }

        const entropy = calculateShannonEntropy(apiKey);
        if (entropy < DEFAULT_GROQ_CONFIG.requiredEntropy) {
            continue;
        }

        if (isProgrammingPattern(apiKey)) {
            continue;
        }

        const existingFindings = await getExistingFindings();
        
        const alreadyFound = existingFindings.some(
            (finding: Finding) => {
                if (finding.secretType !== 'Groq') {
                    return false;
                }
                return Object.values(finding.secretValue).some(
                    (match) => {
                        const groqMatch = match as any;
                        return groqMatch.apiKey === apiKey ||
                               (groqMatch.match && groqMatch.match.apiKey === apiKey);
                    }
                );
            }
        );

        if (alreadyFound) {
            continue;
        }

        const validationResult = await validateGroqCredentials(apiKey);
        
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
                 // Fall back to bundled content if source map processing fails
            }
        }

        const occurrence: GroqOccurrence = {
            secretType: patterns['Groq API Key'].familyName,
            fingerprint: "",
            secretValue: {
                match: {
                    apiKey: apiKey
                }
            },
            filePath: url.split('/').pop() || "",
            url: url,
            type: GROQ_RESOURCE_TYPES['API_KEY'],
            sourceContent: sourceContent,
            validity: "valid"
        };

        occurrence.fingerprint = await computeFingerprint(occurrence.secretValue, 'SHA-512');
        
        results.push(occurrence);
    }
    
    return results;
}