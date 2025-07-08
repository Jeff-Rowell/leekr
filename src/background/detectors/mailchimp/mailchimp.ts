import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "../../../types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { MailchimpOccurrence } from '../../../types/mailchimp';
import { validateMailchimpCredentials } from '../../../utils/validators/mailchimp/mailchimp';
import { MAILCHIMP_RESOURCE_TYPES, DEFAULT_MAILCHIMP_CONFIG } from '../../../config/detectors/mailchimp/mailchimp';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isProgrammingPattern } from '../../../utils/accuracy/programmingPatterns';
import * as sourceMap from '../../../../external/source-map';

export async function detectMailchimpKeys(content: string, url: string): Promise<Occurrence[]> {
    const mailchimpPattern = patterns['Mailchimp API Key'];
    const regex = new RegExp(mailchimpPattern.pattern.source, mailchimpPattern.pattern.flags);
    const matches = Array.from(content.matchAll(regex));
    
    const results: Occurrence[] = [];
    
    if (matches.length === 0) {
        return results;
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
        if (entropy < DEFAULT_MAILCHIMP_CONFIG.requiredEntropy) {
            continue;
        }

        if (isProgrammingPattern(apiKey)) {
            continue;
        }

        const existingFindings = await getExistingFindings();
        
        const alreadyFound = existingFindings.some(
            (finding: Finding) => {
                if (finding.secretType !== 'Mailchimp') {
                    return false;
                }
                return Object.values(finding.secretValue).some(
                    (match) => {
                        const mailchimpMatch = match as any;
                        return mailchimpMatch.apiKey === apiKey ||
                               (mailchimpMatch.match && mailchimpMatch.match.apiKey === apiKey);
                    }
                );
            }
        );

        if (alreadyFound) {
            continue;
        }

        const validationResult = await validateMailchimpCredentials(apiKey);
        
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

        const occurrence: MailchimpOccurrence = {
            secretType: mailchimpPattern.familyName,
            fingerprint: "",
            secretValue: {
                match: {
                    apiKey: apiKey
                }
            },
            filePath: url.split('/').pop() || "",
            url: url,
            type: MAILCHIMP_RESOURCE_TYPES['API_KEY'],
            sourceContent: sourceContent,
            validity: "valid"
        };

        occurrence.fingerprint = await computeFingerprint(occurrence.secretValue, 'SHA-512');
        
        results.push(occurrence);
    }
    
    return results;
}