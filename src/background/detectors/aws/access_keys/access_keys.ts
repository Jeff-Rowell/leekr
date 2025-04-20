import { calculateShannonEntropy } from '../../../utils/entropy';
import { isKnownFalsePositive, falsePositiveSecretPattern } from '../../../utils/falsePositives';
import { validateAWSCredentials } from '../../../utils/aws';
import { AWS_RESOURCE_TYPES, DEFAULT_AWS_CONFIG } from '../../../config/aws';
import { AWSOccurrence, AWSDetectorConfig } from '../../../../types/aws.types';
import { Occurrence } from '../../../../types/findings.types';
import { computeFingerprint } from '../../../utils/computeFingerprint';

let awsConfig: AWSDetectorConfig = { ...DEFAULT_AWS_CONFIG };

export async function detectAwsAccessKeys(content: string, url: string): Promise<Occurrence[]> {
    const awsAccessKeyIdPattern = /\b((?:AKIA|ABIA|ACCA|AIDA)[A-Z0-9]{16})\b/g;
    const awsSecretAccessKeyPattern = /"([A-Za-z0-9+/]{40})"|(?:[^A-Za-z0-9+/]|^)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)/g;
    const accessKeyMatches = content.match(awsAccessKeyIdPattern) || [];

    const secretKeyMatches: string[] = [];
    const matches = content.match(awsSecretAccessKeyPattern)
    matches?.forEach(match => {
        const singleMatchPattern = /"([A-Za-z0-9+/]{40})"|(?:[^A-Za-z0-9+/]|^)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)/;
        const result = match.match(singleMatchPattern);
        if (result) {
            const secretKey = result[1] || result[2];
            secretKeyMatches.push(secretKey);
        }
    })

    if (accessKeyMatches.length === 0 || secretKeyMatches.length === 0) {
        return [];
    }

    const validAccessKeys = accessKeyMatches.filter(key => {
        const entropy = calculateShannonEntropy(key);
        if (entropy < awsConfig.requiredIdEntropy) return false;

        const [isFP] = isKnownFalsePositive(key);
        return !isFP;
    });

    const validSecretKeys = secretKeyMatches.filter(key => {
        const entropy = calculateShannonEntropy(key);
        if (entropy < awsConfig.requiredSecretEntropy) return false;

        const [isFP] = isKnownFalsePositive(key);
        if (isFP) return false;

        return !falsePositiveSecretPattern.test(key);
    });

    if (validAccessKeys.length === 0 || validSecretKeys.length === 0) {
        return [];
    }

    const validOccurrences: Occurrence[] = [];
    for (const aKey of validAccessKeys) {
        for (const sKey of validSecretKeys) {
            const validationResult = await validateAWSCredentials(aKey, sKey);
            if (validationResult.valid) {
                const match: AWSOccurrence = {
                    secretType: "AWS Access & Secret Keys",
                    fingerprint: "",
                    secretValue: {
                        match: {
                            access_key_id: aKey,
                            secret_key_id: sKey
                        }
                    },
                    filePath: url.split('/').pop() || "",
                    url: url,
                    resourceType: AWS_RESOURCE_TYPES[aKey.substring(0, 4)]
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
