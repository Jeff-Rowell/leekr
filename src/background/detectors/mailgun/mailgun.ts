import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "../../../types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { MailgunOccurrence } from '../../../types/mailgun';
import { validateMailgunCredentials } from '../../../utils/validators/mailgun/mailgun';
import { MAILGUN_RESOURCE_TYPES, DEFAULT_MAILGUN_CONFIG } from '../../../config/detectors/mailgun/mailgun';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';
import * as sourceMap from '../../../../external/source-map';


export async function detectMailgunKeys(content: string, url: string): Promise<Occurrence[]> {
    const mailgunPatterns = [
        { name: 'Mailgun Original Token', pattern: patterns['Mailgun Original Token'].pattern },
        { name: 'Mailgun Key Token', pattern: patterns['Mailgun Key Token'].pattern },
        { name: 'Mailgun Hex Token', pattern: patterns['Mailgun Hex Token'].pattern }
    ];
    
    const results: Occurrence[] = [];
    
    for (const patternInfo of mailgunPatterns) {
        const regex = new RegExp(patternInfo.pattern.source, patternInfo.pattern.flags);
        const matches = Array.from(content.matchAll(regex));
        
        if (matches.length === 0) {
            continue;
        }
        
        for (const match of matches) {
            if (!match[1]) {
                continue;
            }

            const apiKey = match[1].trim();
            
            if (!apiKey) {
                continue;
            }

            const entropy = calculateShannonEntropy(apiKey);
            if (entropy < DEFAULT_MAILGUN_CONFIG.requiredEntropy) {
                continue;
            }

            if (isProgrammingPattern(apiKey)) {
                continue;
            }

            const existingFindings = await getExistingFindings();
            
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    if (finding.secretType !== 'Mailgun') {
                        return false;
                    }
                    return Object.values(finding.secretValue).some(
                        (match) => {
                            const mailgunMatch = match as any;
                            return mailgunMatch.apiKey === apiKey ||
                                   (mailgunMatch.match && mailgunMatch.match.apiKey === apiKey);
                        }
                    );
                }
            );

            if (alreadyFound) {
                continue;
            }

            const validationResult = await validateMailgunCredentials(apiKey);
            
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
                }
            }

            const occurrence: MailgunOccurrence = {
                secretType: patterns['Mailgun Original Token'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        apiKey: apiKey
                    }
                },
                filePath: url.split('/').pop() || "",
                url: url,
                type: MAILGUN_RESOURCE_TYPES['API_KEY'],
                sourceContent: sourceContent,
                validity: "valid"
            };

            occurrence.fingerprint = await computeFingerprint(occurrence.secretValue, 'SHA-512');
            
            results.push(occurrence);
        }
    }
    
    return results;
}