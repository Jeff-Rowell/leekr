import { patterns } from '../../../../config/patterns';
import { calculateShannonEntropy } from '../../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../../utils/accuracy/falsePositives';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../../utils/helpers/common';
import { computeFingerprint } from '../../../../utils/helpers/computeFingerprint';
import { MakeMcpOccurrence, MakeMcpSecretValue } from '../../../../types/make';
import { Finding, Occurrence, SourceContent } from '../../../../types/findings.types';
import { validateMakeMcpToken } from '../../../../utils/validators/make/mcp_token/make';
import * as sourceMap from '../../../../../external/source-map';

export async function detectMakeMcpToken(content: string, url: string): Promise<Occurrence[]> {
    const matches = content.match(patterns['Make MCP Token'].pattern) || [];
    
    if (matches.length === 0) {
        return [];
    }

    const validTokens = matches.filter(fullUrl => {
        const entropy = calculateShannonEntropy(fullUrl);
        const entropyThreshold = patterns["Make MCP Token"].entropy;
        if (entropy < entropyThreshold) return false;
        
        const [isFalsePositive] = isKnownFalsePositive(fullUrl);
        if (isFalsePositive) return false;
        
        return true;
    });

    if (validTokens.length === 0) {
        return [];
    }

    const existingFindings = await getExistingFindings();
    const filteredTokens = await Promise.all(
        validTokens.map(async (fullUrl) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    const secretValue = finding.secretValue as MakeMcpSecretValue;
                    if (!secretValue.match) return false;
                    return secretValue.match.full_url === fullUrl;
                }
            );
            return alreadyFound ? null : fullUrl;
        })
    );
    const prunedTokens = filteredTokens.filter((token): token is string => token !== null);
    
    const validOccurrences: Occurrence[] = [];
    
    for (const fullUrl of prunedTokens) {
        const validationResult = await validateMakeMcpToken(fullUrl);
        
        if (validationResult.valid) {
            const tokenPosition = findSecretPosition(content, fullUrl);
            const uuidMatch = fullUrl.match(/\/u\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\//);
            const mcpToken = uuidMatch ? uuidMatch[1] : '';
            
            var newSourceContent: SourceContent = {
                content: JSON.stringify({
                    mcp_token: mcpToken,
                    full_url: fullUrl
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
                    
                }
            }

            const match: MakeMcpOccurrence = {
                secretType: patterns['Make MCP Token'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        mcp_token: mcpToken,
                        full_url: fullUrl,
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