import { computeFingerprint } from "../../../utils/computeFingerprint";
import { NullableOccurrence } from '../../../../types/findings.types';

export async function detectAwsAccessKeys(content: string, url: string): Promise<NullableOccurrence> {
    const awsAccessKeyIdPattern = /\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b/g;
    const awsSecretAccessKeyPattern = /\b(?:[^A-Za-z0-9+/]|^)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)\b/g;
    const accessKeyMatches = content.match(awsAccessKeyIdPattern);
    const secretKeyMatches = content.match(awsSecretAccessKeyPattern);

    if (accessKeyMatches && secretKeyMatches) {
        const match: NullableOccurrence = {
            secretType: "AWS Access & Secret Keys",
            fingerprint: "",
            secretValue: {
                "match": {
                    "access_key_id": accessKeyMatches,
                    "secret_key_id": secretKeyMatches
                }
            },
            filePath: url.split('/').pop()!,
            url: url,
        };
        match.fingerprint = await computeFingerprint(match.secretValue, 'SHA-512');
        return match
    }

    return null;
}
