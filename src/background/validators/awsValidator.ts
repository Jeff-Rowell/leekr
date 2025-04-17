import { Finding, ValidityStatus } from '../../types/findings.types';
import * as objectSha from 'object-sha'

export function detectAwsSecrets(content: string, url: string): Finding {
    const awsAccessKeyIdPattern = /((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})/g;
    const awsSecretAccessKeyPattern = /(?:[^A-Za-z0-9+/]|^)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)/g;

    const match: Finding = {
        secretType: "",
        filePath: "",
        validity: "valid",
        validatedAt: "",
        secretValue: {},
        fingerprint: "",
        url: "",
    };
    const accessKeyMatches = content.match(awsAccessKeyIdPattern);
    const secretKeyMatches = content.match(awsSecretAccessKeyPattern);

    if (accessKeyMatches && secretKeyMatches) {
        match.secretType = "AWS Access & Secret Keys"
        match.filePath = url.split('/').pop()!
        match.validity = "valid"
        match.validatedAt = new Date().toISOString();
        match.secretValue = {
            "match": {
                "access_key_id": accessKeyMatches,
                "secret_key_id": secretKeyMatches
            }
        }
        match.url = url;
        objectSha.digest(match, 'SHA-512')
            .then((digest: string) => {
                match.fingerprint = digest;
            })
            .catch(() => {
                console.log("Error computing sha512 of match")
            });
    }

    return match;
}
