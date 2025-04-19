import { detectAwsAccessKeys } from './detectors/aws/access_keys/access_keys';
import { validateAwsAccessKeys } from './validators/aws/access_keys/access_keys';
import { Finding, NullableFinding, NullableOccurrence } from '../types/findings.types';

export async function findSecrets(content: string, url: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const awsMatches: NullableOccurrence = await detectAwsAccessKeys(content, url);

    if (awsMatches) { // If AWS access keys were matched
        const f: Finding = {
            numOccurrences: 0,
            secretType: awsMatches.secretType,
            secretValue: awsMatches.secretValue,
            validity: "valid",
            validatedAt: new Date().toISOString(),
            fingerprint: awsMatches.fingerprint,
            occurrences: new Set([awsMatches])
        }
        console.log("awsMatches.fingerprint", awsMatches.fingerprint);
        f.numOccurrences = f.occurrences.size
        findings.push(f)
    }

    return findings;
}
