import { patterns } from '../../../../config/patterns';
import { calculateShannonEntropy } from '../../../../utils/accuracy/entropy';
import { falsePositiveSecretPattern, isKnownFalsePositive } from '../../../../utils/accuracy/falsePositives';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../../utils/helpers/common';
import { computeFingerprint } from '../../../../utils/helpers/computeFingerprint';
import { AWSOccurrence, AWSSecretValue } from '../../../../types/aws.types';
import { Finding, Occurrence, SourceContent } from '../../../../types/findings.types';
import { validateAWSCredentials } from '../../../../utils/validators/aws/aws_session_keys/aws';
import * as sourceMap from '../../../../../external/source-map';
import { AWS_RESOURCE_TYPES } from '../../../../config/detectors/aws/aws_session_keys/aws';


export async function detectAwsSessionKeys(content: string, url: string): Promise<Occurrence[]> {
    const accessKeyMatches = content.match(patterns['AWS Session Key ID'].pattern) || [];
    const secretKeyMatches: string[] = [];
    findData(content, secretKeyMatches, patterns['AWS Secret Key'].pattern)
    const sessionKeyMatches: string[] = [];
    findData(content, sessionKeyMatches, patterns['AWS Session Key'].pattern)
    if (accessKeyMatches.length === 0 || secretKeyMatches.length === 0 || sessionKeyMatches.length === 0) {
        return [];
    }

    const validAccessKeys = accessKeyMatches.filter(key => {
        const entropy = calculateShannonEntropy(key);
        const accessKeyEntropyThreshold = patterns["AWS Session Key ID"].entropy;
        if (entropy < accessKeyEntropyThreshold) return false;

        const [isFP] = isKnownFalsePositive(key);
        return !isFP;
    });

    const validSecretKeys = secretKeyMatches.filter(key => {
        if (key) {
            const entropy = calculateShannonEntropy(key);
            const secretKeyEntropyThreshold = patterns["AWS Secret Key"].entropy;
            if (entropy < secretKeyEntropyThreshold) return false;

            const [isFP] = isKnownFalsePositive(key);
            if (isFP) return false;

            return !falsePositiveSecretPattern.test(key);
        } else {
            return false
        }
    });

    const validSessionKeys = sessionKeyMatches.filter(key => {
        const entropy = calculateShannonEntropy(key);
        const secretKeyEntropyThreshold = patterns["AWS Session Key"].entropy;
        if (entropy < secretKeyEntropyThreshold) return false;

        const [isFP] = isKnownFalsePositive(key);
        if (isFP) return false;

        return !falsePositiveSecretPattern.test(key);
    });

    if (validAccessKeys.length === 0 || validSecretKeys.length === 0 || validSessionKeys.length === 0) {
        return [];
    }

    const existingFindings = await getExistingFindings();
    const filteredAccessKeys = await Promise.all(
        validAccessKeys.map(async (aKey) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    return Object.values(finding.secretValue).some(
                        (match: AWSSecretValue) => {
                            return Object.values(match).includes(aKey);
                        }
                    )
                }
            );
            return alreadyFound ? null : aKey;
        })
    );
    const prunedAccessKeys = filteredAccessKeys.filter((key): key is string => key !== null);

    const validOccurrences: Occurrence[] = [];
    for (const accessKey of prunedAccessKeys) {
        for (const secretKey of validSecretKeys) {
            for (const sessionKey of validSessionKeys) {
                if (!await checkSessionToken(sessionKey, secretKey)) {
                    continue
                }
                const validationResult = await validateAWSCredentials(accessKey, secretKey, sessionKey);
                if (validationResult.valid) {
                    var newSourceContent: SourceContent = {
                        content: JSON.stringify({
                            access_key_id: accessKey,
                            secret_key_id: secretKey,
                            session_key_id: sessionKey
                        }),
                        contentFilename: url.split('/').pop() || "",
                        contentStartLineNum: -1,
                        contentEndLineNum: -1,
                        exactMatchNumbers: [-1]
                    }
                    const sourceMapUrl = getSourceMapUrl(url, content);
                    if (sourceMapUrl) {
                        const sourceMapResponse = await fetch(sourceMapUrl);
                        const sourceMapContent = await sourceMapResponse.text();
                        sourceMap.SourceMapConsumer.initialize({
                            "lib/mappings.wasm": chrome.runtime.getURL('libs/mappings.wasm'),
                        });
                        await sourceMap.SourceMapConsumer.with(sourceMapContent, null, (consumer: any) => {
                            const accessKeyPosition = findSecretPosition(content, accessKey);
                            const secretKeyPosition = findSecretPosition(content, secretKey);
                            const sessionKeyPosition = findSecretPosition(content, sessionKey);
                            const accessKeyOriginalPosition = consumer.originalPositionFor({
                                line: accessKeyPosition.line,
                                column: accessKeyPosition.column
                            });
                            const secretKeyOriginalPosition = consumer.originalPositionFor({
                                line: secretKeyPosition.line,
                                column: secretKeyPosition.column
                            });
                            const sessionKeyOriginalPosition = consumer.originalPositionFor({
                                line: sessionKeyPosition.line,
                                column: sessionKeyPosition.column
                            });
                            if (accessKeyOriginalPosition.source && secretKeyOriginalPosition.source && sessionKeyOriginalPosition.source
                                && accessKeyOriginalPosition.source === secretKeyOriginalPosition.source &&
                                secretKeyOriginalPosition.source === sessionKeyOriginalPosition.source) {
                                const sourceContent = consumer.sourceContentFor(accessKeyOriginalPosition.source);
                                newSourceContent = {
                                    content: sourceContent,
                                    contentFilename: accessKeyOriginalPosition.source,
                                    contentStartLineNum: Math.min(accessKeyOriginalPosition.line, secretKeyOriginalPosition.line, sessionKeyOriginalPosition.line) - 5,
                                    contentEndLineNum: Math.max(accessKeyOriginalPosition.line, secretKeyOriginalPosition.line, sessionKeyOriginalPosition.line) + 5,
                                    exactMatchNumbers: [accessKeyOriginalPosition.line, secretKeyOriginalPosition.line, sessionKeyOriginalPosition.line]
                                };
                            }
                        });
                    }
                    const match: AWSOccurrence = {
                        secretType: patterns['AWS Session Key'].familyName,
                        fingerprint: "",
                        secretValue: {
                            match: {
                                access_key_id: accessKey,
                                secret_key_id: secretKey,
                                session_key_id: sessionKey,
                            }
                        },
                        filePath: url.split('/').pop() || "",
                        url: url,
                        resourceType: AWS_RESOURCE_TYPES[accessKey.substring(0, 4)],
                        sourceContent: newSourceContent
                    };
                    match.validity = "valid";
                    match.accountId = validationResult.accountId;
                    match.arn = validationResult.arn;
                    match.fingerprint = await computeFingerprint(match.secretValue, 'SHA-512');
                    validOccurrences.push(match);
                }
            }
        }
    }

    if (validOccurrences.length > 0) {
        return validOccurrences;
    } else {
        return [];
    }
};

async function findData(content: string, matchArray: string[], pattern: RegExp) {
    const matches = content.match(pattern)
    matches?.forEach(match => {
        // Removes the global flag if its set 
        const singleMatchPattern = new RegExp(pattern.source)
        const result = match.match(singleMatchPattern);
        if (result) {
            const sessionKey = result[1];
            matchArray.push(sessionKey);
        }
    })
}

export async function checkSessionToken(sessionToken: string, secret: string): Promise<boolean> {
    if (!(sessionToken.includes("YXdz") || sessionToken.includes("Jb3JpZ2luX2Vj") || sessionToken.includes(secret))) {
        return false
    }
    return true
}
