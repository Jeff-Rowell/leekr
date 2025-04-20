import { detectAwsAccessKeys } from './detectors/aws/access_keys/access_keys';
import { Finding, Occurrence } from '../types/findings.types';

export async function findSecrets(content: string, url: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const awsMatches: Occurrence[] = await detectAwsAccessKeys(content, url);

    if (awsMatches.length > 0) {
        awsMatches.forEach(occurrence => {
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