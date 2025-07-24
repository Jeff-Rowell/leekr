import { patterns } from '../../../../config/patterns';
import { calculateShannonEntropy } from '../../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../../utils/accuracy/falsePositives';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../../utils/helpers/common';
import { computeFingerprint } from '../../../../utils/helpers/computeFingerprint';
import { MakeOccurrence, MakeSecretValue } from '../../../../types/make';
import { Finding, Occurrence, SourceContent } from '../../../../types/findings.types';
import { validateMakeApiToken } from '../../../../utils/validators/make/api_token/make';
import * as sourceMap from '../../../../../external/source-map';

export async function detectMakeApiToken(content: string, url: string): Promise<Occurrence[]> {
    const matches = content.match(patterns['Make API Token'].pattern) || [];
    
    if (matches.length === 0) {
        return [];
    }

    const validTokens = matches.filter(token => {
        const entropy = calculateShannonEntropy(token);
        const entropyThreshold = patterns["Make API Token"].entropy;
        
        if (entropy < entropyThreshold) return false;
        
        const [isFalsePositive, pattern] = isKnownFalsePositive(token);
        if (isFalsePositive) return false;
        
        return true;
    });


    if (validTokens.length === 0) {
        return [];
    }

    const existingFindings = await getExistingFindings();
    
    const filteredTokens = await Promise.all(
        validTokens.map(async (token) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    const secretValue = finding.secretValue as MakeSecretValue;
                    if (!secretValue.match) return false;
                    return secretValue.match.api_token === token;
                }
            );
            return alreadyFound ? null : token;
        })
    );
    const prunedTokens = filteredTokens.filter((token): token is string => token !== null);
    
    const validOccurrences: Occurrence[] = [];
    
    for (const token of prunedTokens) {
        const validationResult = await validateMakeApiToken(token);
        
        if (validationResult.valid) {
            const tokenPosition = findSecretPosition(content, token);
            var newSourceContent: SourceContent = {
                content: JSON.stringify({
                    api_token: token
                }),
                contentFilename: url.split('/').pop() || "",
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            }
            
            const sourceMapUrl = getSourceMapUrl(url, content);
            if (sourceMapUrl) {
                try {
                    const sourceMapResponse = await fetch(sourceMapUrl);
                    const sourceMapContent = await sourceMapResponse.text();
                    sourceMap.SourceMapConsumer.initialize({
                        "lib/mappings.wasm": chrome.runtime.getURL('libs/mappings.wasm'),
                    });
                    await sourceMap.SourceMapConsumer.with(sourceMapContent, null, (consumer: any) => {
                        const originalPosition = consumer.originalPositionFor({
                            line: tokenPosition.line,
                            column: tokenPosition.column
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
                } catch (sourceMapError) {
                    // If source map processing fails, continue with default source content
                    // newSourceContent is already set to default values above
                }
            }

            const match: MakeOccurrence = {
                secretType: patterns['Make API Token'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        api_token: token,
                    }
                },
                filePath: url.split('/').pop() || "",
                url: url,
                sourceContent: newSourceContent
            };
            match.validity = "valid";
            match.fingerprint = await computeFingerprint(match.secretValue, 'SHA-512');
            validOccurrences.push(match);
        }
    }

    return validOccurrences;
};