import * as sourceMap from '../../../../../external/source-map';
import { AWS_RESOURCE_TYPES } from '../../../../config/detectors/aws/aws_access_keys/aws';
import { patterns } from '../../../../config/patterns';
import { AWSOccurrence, AWSSecretValue } from '../../../../types/aws.types';
import { Finding, Occurrence, SourceContent } from '../../../../types/findings.types';
import { calculateShannonEntropy } from '../../../../utils/accuracy/entropy';
import { falsePositiveSecretPattern, isKnownFalsePositive } from '../../../../utils/accuracy/falsePositives';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../../utils/helpers/common';
import { computeFingerprint } from '../../../../utils/helpers/computeFingerprint';
import { validateAWSCredentials } from '../../../../utils/validators/aws/aws_access_keys/aws';

export async function detectAwsAccessKeys(content: string, url: string): Promise<Occurrence[]> {
    const accessKeyMatches = content.match(patterns['AWS Access Key'].pattern) || [];
    const secretKeyMatches: string[] = [];
    const matches = content.match(patterns['AWS Secret Key'].pattern)
    matches?.forEach(match => {
        // Removes the global flag if its set 
        const singleMatchPattern = new RegExp(patterns['AWS Secret Key'].pattern.source)
        const result = match.match(singleMatchPattern);
        if (result) {
            const secretKey = result[1];
            secretKeyMatches.push(secretKey);
        }
    })

    if (accessKeyMatches.length === 0 || secretKeyMatches.length === 0) {
        return [];
    }

    const validAccessKeys = accessKeyMatches.filter(key => {
        const entropy = calculateShannonEntropy(key);
        const accessKeyEntropyThreshold = patterns["AWS Access Key"].entropy;
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

    if (validAccessKeys.length === 0 || validSecretKeys.length === 0) {
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
                    );
                }
            );
            return alreadyFound ? null : aKey;
        })
    );
    const prunedAccessKeys = filteredAccessKeys.filter((key): key is string => key !== null);

    const validOccurrences: Occurrence[] = [];
    for (const aKey of prunedAccessKeys) {
        for (const sKey of validSecretKeys) {
            const validationResult = await validateAWSCredentials(aKey, sKey);
            if (validationResult.valid) {
                var newSourceContent: SourceContent = {
                    content: JSON.stringify({
                        access_key_id: aKey,
                        secret_key_id: sKey
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
                        const accessKeyPosition = findSecretPosition(content, aKey);
                        const secretKeyPosition = findSecretPosition(content, sKey);
                        const accessKeyOriginalPosition = consumer.originalPositionFor({
                            line: accessKeyPosition.line,
                            column: accessKeyPosition.column
                        });
                        const secretKeyOriginalPosition = consumer.originalPositionFor({
                            line: secretKeyPosition.line,
                            column: secretKeyPosition.column
                        });
                        if (accessKeyOriginalPosition.source && secretKeyOriginalPosition.source
                            && accessKeyOriginalPosition.source === secretKeyOriginalPosition.source) {
                            const sourceContent = consumer.sourceContentFor(accessKeyOriginalPosition.source);
                            newSourceContent = {
                                content: sourceContent,
                                contentFilename: accessKeyOriginalPosition.source,
                                contentStartLineNum: accessKeyOriginalPosition.line < secretKeyOriginalPosition.line ?
                                    accessKeyOriginalPosition.line - 5 :
                                    secretKeyOriginalPosition.line - 5,
                                contentEndLineNum: accessKeyOriginalPosition.line > secretKeyOriginalPosition.line ?
                                    accessKeyOriginalPosition.line + 5 :
                                    secretKeyOriginalPosition.line + 5,
                                exactMatchNumbers: [accessKeyOriginalPosition.line, secretKeyOriginalPosition.line]
                            };
                        }
                    });
                }
                const match: AWSOccurrence = {
                    secretType: patterns['AWS Secret Key'].familyName,
                    fingerprint: "",
                    secretValue: {
                        match: {
                            access_key_id: aKey,
                            secret_key_id: sKey
                        }
                    },
                    filePath: url.split('/').pop() || "",
                    url: url,
                    resourceType: AWS_RESOURCE_TYPES[aKey.substring(0, 4)],
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

    if (validOccurrences.length > 0) {
        return validOccurrences;
    } else {
        return [];
    }
};
