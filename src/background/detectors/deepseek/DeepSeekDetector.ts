import * as sourceMap from '../../../../external/source-map';
import { SecretDetector } from '../detector.interface';
import { DeepSeekOccurrence } from '../../../types/deepseek';
import { deepseekConfig } from '../../../config/detectors/deepseek/deepseek';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS } from '../../../utils/accuracy/programmingPatterns';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';
import { Occurrence, SourceContent } from '../../../types/findings.types';
import { findSecretPosition, getSourceMapUrl } from '../../../utils/helpers/common';

export class DeepSeekDetector implements SecretDetector {
    readonly type = 'DeepSeek';
    readonly name = 'DeepSeek';
    
    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectDeepSeekKeys(content, url);
    }
}

export async function detectDeepSeekKeys(content: string, url: string): Promise<DeepSeekOccurrence[]> {
    const occurrences: DeepSeekOccurrence[] = [];
    const apiKeyPattern = deepseekConfig.patterns.apiKey.pattern;

    let match;
    while ((match = apiKeyPattern.exec(content)) !== null) {
        const apiKey = match[1];
        const fullMatch = match[0];
        
        if (isValidApiKey(apiKey) && !isFalsePositive(content, match.index, apiKey)) {
            const startIndex = match.index;
            const endIndex = startIndex + fullMatch.length;

            let newSourceContent: SourceContent = {
                content: extractSourceContent(content, startIndex, endIndex),
                contentFilename: extractFilename(url),
                contentStartLineNum: getLineNumber(content, startIndex),
                contentEndLineNum: getLineNumber(content, endIndex),
                exactMatchNumbers: [startIndex, endIndex]
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
                        const apiKeyPosition = findSecretPosition(content, apiKey);
                        const apiKeyOriginalPosition = consumer.originalPositionFor({
                            line: apiKeyPosition.line,
                            column: apiKeyPosition.column
                        });
                        if (apiKeyOriginalPosition.source) {
                            const sourceContent = consumer.sourceContentFor(apiKeyOriginalPosition.source);
                            if (sourceContent) {
                                newSourceContent = {
                                    content: sourceContent,
                                    contentFilename: apiKeyOriginalPosition.source,
                                    contentStartLineNum: Math.max(1, apiKeyOriginalPosition.line - 5),
                                    contentEndLineNum: apiKeyOriginalPosition.line + 5,
                                    exactMatchNumbers: [apiKeyOriginalPosition.line]
                                };
                            }
                        }
                    });
                } catch (error) {
                    console.warn('Failed to process source map for DeepSeek detection:', error);
                }
            }

            const occurrence: DeepSeekOccurrence = {
                fingerprint: generateFingerprint(apiKey, url),
                secretType: "DeepSeek",
                filePath: url,
                url: url,
                type: "API Key",
                secretValue: {
                    match: {
                        apiKey: apiKey
                    }
                },
                sourceContent: newSourceContent
            };

            occurrences.push(occurrence);
        }
    }

    return occurrences;
}

function isValidApiKey(apiKey: string): boolean {
    if (!apiKey.startsWith('sk-') || apiKey.length !== 35) {
        return false;
    }

    const entropy = calculateShannonEntropy(apiKey);
    return entropy >= deepseekConfig.patterns.apiKey.entropy
}

function isFalsePositive(content: string, index: number, apiKey: string): boolean {
    const [isKnownFP] = isKnownFalsePositive(apiKey);
    if (isKnownFP) {
        return true;
    }

    const contextStart = Math.max(0, index - 200);
    const contextEnd = Math.min(content.length, index + 200);
    const context = content.slice(contextStart, contextEnd);

    for (const pattern of COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS) {
        if (pattern.test(context)) {
            return true;
        }
    }

    return false;
}

function generateFingerprint(apiKey: string, filePath: string): string {
    const hash = simpleHash(apiKey + filePath);
    return `deepseek-${hash}`;
}

function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).slice(0, 8);
}

function extractSourceContent(content: string, startIndex: number, endIndex: number): string {
    const lineStart = content.lastIndexOf('\n', startIndex);
    const lineEnd = content.indexOf('\n', endIndex);
    
    const start = lineStart === -1 ? 0 : lineStart + 1;
    const end = lineEnd === -1 ? content.length : lineEnd;
    
    return content.slice(start, end);
}

function extractFilename(filePath: string): string {
    return filePath.split('/').pop() || filePath;
}

function getLineNumber(content: string, index: number): number {
    return content.slice(0, index).split('\n').length;
}