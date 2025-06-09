import { Finding, Occurrence } from '../types/findings.types';
import { detectAwsAccessKeys } from './detectors/aws/access_keys/access_keys';
import { detectAwsSessionKeys } from './detectors/aws/session_keys/session_keys';

export async function findSecrets(content: string, url: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const awsAccessKeyMatches: Occurrence[] = await detectAwsAccessKeys(content, url);
    const awsSessionKeyMatches: Occurrence[] = await detectAwsSessionKeys(content, url);

    if (awsAccessKeyMatches.length > 0) {
        awsAccessKeyMatches.forEach(occurrence => {
            const f: Finding = {
                numOccurrences: 1,
                secretType: occurrence.secretType,
                secretValue: occurrence.secretValue,
                validity: "valid",
                validatedAt: new Date().toISOString(),
                fingerprint: occurrence.fingerprint,
                occurrences: new Set([occurrence])
            }
            findings.push(f);
        });
    }
    if (awsSessionKeyMatches.length > 0) {
        awsSessionKeyMatches.forEach(occurrence => {
            const f: Finding = {
                numOccurrences: 1,
                secretType: occurrence.secretType,
                secretValue: occurrence.secretValue,
                validity: "valid",
                validatedAt: new Date().toISOString(),
                fingerprint: occurrence.fingerprint,
                occurrences: new Set([occurrence])
            }
            findings.push(f);
        });
    }

    return findings;
}