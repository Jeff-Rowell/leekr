import { detectAwsSecrets } from './validators/awsValidator';
import { Finding } from '../types/findings.types';

export function matchPatterns(content: string, url: string): Finding[] {
    const findings: Finding[] = [];

    const awsMatches: Finding = detectAwsSecrets(content, url);
    if (awsMatches.url !== "") {
        findings.push(awsMatches);
    }

    return findings;
}
