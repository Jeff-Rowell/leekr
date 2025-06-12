import { Finding, Occurrence } from '../types/findings.types';
import { detectAwsAccessKeys } from './detectors/aws/access_keys/access_keys';
import { detectAwsSessionKeys } from './detectors/aws/session_keys/session_keys';

export async function findSecrets(content: string, url: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    const awsAccessKeyMatches: Occurrence[] = await detectAwsAccessKeys(content, url);
    createFindings(findings, awsAccessKeyMatches)

    const awsSessionKeyMatches: Occurrence[] = await detectAwsSessionKeys(content, url);
    createFindings(findings, awsSessionKeyMatches)

    return findings;
}

async function createFindings(findings: Finding[], matches: Occurrence[]) {
    if (matches.length > 0) {
        matches.forEach(occurrence => {
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
}