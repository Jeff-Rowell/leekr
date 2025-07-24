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
    console.log('[Make Detector] Starting detection on URL:', url);
    console.log('[Make Detector] Content length:', content.length);
    console.log('[Make Detector] Using pattern:', patterns['Make API Token'].pattern);
    
    const matches = content.match(patterns['Make API Token'].pattern) || [];
    console.log('[Make Detector] Pattern matches found:', matches.length, matches);
    
    if (matches.length === 0) {
        console.log('[Make Detector] No matches found, returning empty array');
        return [];
    }

    const validTokens = matches.filter(token => {
        const entropy = calculateShannonEntropy(token);
        const entropyThreshold = patterns["Make API Token"].entropy;
        console.log('[Make Detector] Token entropy check:', { token, entropy, entropyThreshold, passes: entropy >= entropyThreshold });
        
        if (entropy < entropyThreshold) return false;
        
        const [isFalsePositive, pattern] = isKnownFalsePositive(token);
        console.log('[Make Detector] False positive check:', { token, isFalsePositive, pattern });
        if (isFalsePositive) return false;
        
        return true;
    });

    console.log('[Make Detector] Tokens after entropy/false positive filtering:', validTokens.length, validTokens);

    if (validTokens.length === 0) {
        console.log('[Make Detector] No valid tokens after filtering, returning empty array');
        return [];
    }

    const existingFindings = await getExistingFindings();
    console.log('[Make Detector] Existing findings count:', existingFindings.length);
    
    const filteredTokens = await Promise.all(
        validTokens.map(async (token) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    const secretValue = finding.secretValue as MakeSecretValue;
                    if (!secretValue.match) return false;
                    return secretValue.match.api_token === token;
                }
            );
            console.log('[Make Detector] Duplicate check:', { token, alreadyFound });
            return alreadyFound ? null : token;
        })
    );
    const prunedTokens = filteredTokens.filter((token): token is string => token !== null);
    console.log('[Make Detector] Tokens after duplicate filtering:', prunedTokens.length, prunedTokens);
    
    const validOccurrences: Occurrence[] = [];
    console.log('[Make Detector] Starting validation for', prunedTokens.length, 'tokens');
    
    for (const token of prunedTokens) {
        console.log('[Make Detector] Validating token:', token);
        const validationResult = await validateMakeApiToken(token);
        console.log('[Make Detector] Validation result:', { token, valid: validationResult.valid, error: validationResult.error });
        
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
            console.log('[Make Detector] Created valid occurrence:', { token, fingerprint: match.fingerprint });
            validOccurrences.push(match);
        }
    }

    console.log('[Make Detector] Final results:', validOccurrences.length, 'valid occurrences found');
    return validOccurrences;
};