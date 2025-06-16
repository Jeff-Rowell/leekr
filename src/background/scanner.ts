import { Finding, Occurrence } from '../types/findings.types';
import { detectAwsAccessKeys } from './detectors/aws/access_keys/access_keys';
import { detectAwsSessionKeys } from './detectors/aws/session_keys/session_keys';
import { detectAnthropicKeys } from './detectors/anthropic/anthropic';

export async function findSecrets(content: string, url: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    // TODO: refactor this with a factory and don't block on each scan
    const awsAccessKeyMatches: Occurrence[] = await detectAwsAccessKeys(content, url);
    createFindings(findings, awsAccessKeyMatches)

    const awsSessionKeyMatches: Occurrence[] = await detectAwsSessionKeys(content, url);
    createFindings(findings, awsSessionKeyMatches)

    const anthropicKeyMatches: Occurrence[] = await detectAnthropicKeys(content, url);
    createFindings(findings, anthropicKeyMatches)

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