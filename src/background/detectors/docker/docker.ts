import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "../../../types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { DockerOccurrence } from '../../../types/docker';
import { validateDockerCredentials } from '../../../utils/validators/docker/docker';
import { DOCKER_RESOURCE_TYPES, DEFAULT_DOCKER_CONFIG } from '../../../config/detectors/docker/docker';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';

interface DockerAuth {
    auth?: string;
    username?: string;
    password?: string;
    email?: string;
}

interface ProcessedAuth {
    auth: string;
    username: string;
    password: string;
}

export async function detectDockerKeys(content: string, url: string): Promise<Occurrence[]> {
    // Create a new regex instance to avoid global flag state issues
    const dockerPattern = patterns['Docker Auth Config'].pattern;
    const regex = new RegExp(dockerPattern.source, dockerPattern.flags);
    
    const matches = Array.from(content.matchAll(regex));
    
    if (matches.length === 0) {
        return [];
    }

    const results: Occurrence[] = [];
    
    for (const match of matches) {
        const dockerAuths = parseDockerAuthConfig(match[0]);
        
        if (!dockerAuths || Object.keys(dockerAuths).length === 0) {
            continue;
        }
        
        // Store the original match for source map highlighting
        const originalMatch = match[0];
        
        // Process each registry in the auths
        for (const [registry, auth] of Object.entries(dockerAuths)) {
            const processedAuth = processDockerAuth(auth);
            if (!processedAuth) {
                continue;
            }
            
            const credentials = {
                registry: registry,
                auth: processedAuth.auth,
                username: processedAuth.username,
                password: processedAuth.password,
                email: auth.email || ""
            };
            
            // Check auth token entropy
            if (credentials.auth) {
                const authEntropy = calculateShannonEntropy(credentials.auth);
                
                // Auth tokens should have decent entropy (base64 encoded credentials)
                if (authEntropy < DEFAULT_DOCKER_CONFIG.requiredAuthEntropy) {
                    continue;
                }
            }
            
            // Check password entropy (if present and not empty)
            if (credentials.password && credentials.password.length > 0) {
                const passwordEntropy = calculateShannonEntropy(credentials.password);
                
                // Passwords should have some entropy
                if (passwordEntropy < DEFAULT_DOCKER_CONFIG.requiredPasswordEntropy) {
                    continue;
                }
            }

            const credentialsJson = JSON.stringify({
                auths: {
                    [credentials.registry]: {
                        auth: credentials.auth,
                        username: credentials.username,
                        password: credentials.password,
                        email: credentials.email
                    }
                }
            });

            const existingFindings = await getExistingFindings();
            
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    if (finding.secretType !== 'Docker') {
                        return false;
                    }
                    return Object.values(finding.secretValue).some(
                        (match) => {
                            const dockerMatch = match as any;
                            return dockerMatch.auth === credentials.auth || 
                                   dockerMatch.registry === credentials.registry ||
                                   (dockerMatch.match && (dockerMatch.match.auth === credentials.auth || dockerMatch.match.registry === credentials.registry));
                        }
                    );
                }
            );

            if (alreadyFound) {
                continue;
            }

            const validationResult = await validateDockerCredentials(credentialsJson);
            
            if (!validationResult.valid) {
                continue;
            }

            const sourceContent: SourceContent = {
                content: credentialsJson,
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
                        const position = findSecretPosition(content, originalMatch);
                        const originalPosition = consumer.originalPositionFor({
                            line: position.line,
                            column: position.column
                        });
                        if (originalPosition.source && originalPosition.line) {
                            const originalSource = consumer.sourceContentFor(originalPosition.source);
                            if (originalSource) {
                                // Find the complete Docker config in the original source
                                const originalLines = originalSource.split('\n');
                                const startLine = originalPosition.line - 1; // Convert to 0-based index
                                
                                // Find the start of the Docker config by looking backwards for opening brace
                                let configStartLine = startLine;
                                for (let i = startLine; i >= 0; i--) {
                                    if (originalLines[i].includes('dockerJson') || originalLines[i].includes('const') || originalLines[i].includes('let') || originalLines[i].includes('var')) {
                                        configStartLine = i;
                                        break;
                                    }
                                    if (originalLines[i].trim().endsWith('= {') || originalLines[i].trim() === '{') {
                                        configStartLine = i;
                                        break;
                                    }
                                }
                                
                                // Find the end of the Docker config by counting braces
                                let braceCount = 0;
                                let configEndLine = startLine;
                                let foundStart = false;
                                
                                for (let i = configStartLine; i < originalLines.length; i++) {
                                    const line = originalLines[i];
                                    const openBraces = (line.match(/\{/g) || []).length;
                                    const closeBraces = (line.match(/\}/g) || []).length;
                                    
                                    if (!foundStart && openBraces > 0) {
                                        foundStart = true;
                                        braceCount = openBraces - closeBraces;
                                    } else if (foundStart) {
                                        braceCount += openBraces - closeBraces;
                                    }
                                    
                                    if (foundStart && braceCount <= 0) {
                                        configEndLine = i;
                                        break;
                                    }
                                }
                                
                                // Generate array of all line numbers that should be highlighted (1-based)
                                const allLineNumbers: number[] = [];
                                for (let i = configStartLine + 1; i <= configEndLine + 1; i++) {
                                    allLineNumbers.push(i);
                                }
                                
                                sourceContent.content = originalSource;
                                sourceContent.contentFilename = originalPosition.source;
                                sourceContent.contentStartLineNum = Math.max(1, configStartLine + 1 - 5);
                                sourceContent.contentEndLineNum = configEndLine + 1 + 10;
                                sourceContent.exactMatchNumbers = allLineNumbers;
                            }
                        }
                    });
                } catch (error) {
                    // Continue with default source content
                }
            }

            const occurrence: DockerOccurrence = {
                secretType: patterns['Docker Auth Config'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        registry: credentials.registry,
                        auth: credentials.auth,
                        username: credentials.username,
                        password: credentials.password,
                        email: credentials.email
                    }
                },
                filePath: url.split('/').pop() || "",
                url: url,
                type: DOCKER_RESOURCE_TYPES[validationResult.type],
                sourceContent: sourceContent,
                validity: "valid"
            };

            occurrence.fingerprint = await computeFingerprint(occurrence.secretValue, 'SHA-512');
            
            results.push(occurrence);
        }
    }
    
    return results;
}

// Parse Docker auth config JSON, handling both quoted and unquoted keys
function parseDockerAuthConfig(configString: string): Record<string, DockerAuth> | null {
    // First, try to find a complete auths structure by looking for balanced braces
    const authsPattern = patterns['Docker Auths Structure'].pattern;
    const authsRegex = new RegExp(authsPattern.source, authsPattern.flags);
    let authsMatch = authsRegex.exec(configString);
    
    if (!authsMatch) {
        return null;
    }
    
    // Find the complete auths block by counting braces
    let braceCount = 1;
    let startIndex = authsMatch.index + authsMatch[0].length;
    let endIndex = startIndex;
    
    for (let i = startIndex; i < configString.length && braceCount > 0; i++) {
        if (configString[i] === '{') braceCount++;
        else if (configString[i] === '}') braceCount--;
        endIndex = i;
    }
    
    const authsContent = configString.substring(startIndex, endIndex);
    
    // Try to parse the full auths block as JSON first
    try {
        let fullAuthsString = `{${authsContent}}`;
        
        // Try parsing as-is first
        try {
            const parsed = JSON.parse(fullAuthsString);
            return parsed;
        } catch (firstError) {
            // Fix unquoted property names - common in JavaScript bundles
            fullAuthsString = fullAuthsString.replace(/([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:/g, '$1"$2":');
            
            const parsed = JSON.parse(fullAuthsString);
            return parsed;
        }
    } catch (error) {
        // If JSON parsing fails completely, return null 
        return null;
    }
}


function processDockerAuth(auth: DockerAuth): ProcessedAuth | null {
    let username = "";
    let password = "";
    
    // If we have username and password directly, use them
    if (auth.username && auth.password) {
        username = auth.username;
        password = auth.password;
    }
    
    // If we have auth token, decode it to get credentials
    if (auth.auth) {
        try {
            const decoded = atob(auth.auth);
            const parts = decoded.split(':');
            if (parts.length === 2) {
                // If we already have username/password from fields, verify they match
                if (username && password) {
                    // Return null if there's a mismatch between auth token and explicit fields
                    if (parts[0] !== username || parts[1] !== password) {
                        return null;
                    }
                } else {
                    // Use credentials from auth token
                    username = parts[0];
                    password = parts[1];
                }
            }
        } catch (error) {
            // Return null if we can't decode the auth token
            return null;
        }
    }
    
    // Must have both username and password
    if (!username || !password) {
        return null;
    }
    
    // Create base64 auth token
    const finalAuth = btoa(`${username}:${password}`);
    
    // If original auth was provided, verify our generated auth matches
    if (auth.auth && finalAuth !== auth.auth) {
        return null;
    }
    
    return {
        auth: finalAuth,
        username: username,
        password: password
    };
}