import { Finding } from "src/types/findings.types";
import { validateAWSCredentials } from "../../../background/utils/aws";

export async function awsValidityHelper(finding: Finding): Promise<void> {
    for (const awsOccurrence of Object.values(finding.secretValue)) {
        console.log("awsOccurrence = ", awsOccurrence)
        const validationResult = await validateAWSCredentials(
            awsOccurrence.access_key_id,
            awsOccurrence.secret_key_id
        );
        console.log("validationResult = ", validationResult)
        if (!validationResult.valid) {
            chrome.storage.local.get(['findings'], async function (result) {
                let existingFindings: Finding[] = result.findings || [];
                console.log("existingFindings = ", existingFindings)
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                console.log("index = ", index)
                existingFindings[index].validity = "invalid";
                existingFindings[index].validatedAt = new Date().toISOString();
                chrome.storage.local.set({ findings: existingFindings }, () => { });
            });
            break;
        } else if (finding.validity === 'invalid') {
            // this handles situations where the key was deactivated and then re-activated later on
            chrome.storage.local.get(['findings'], async function (result) {
                let existingFindings: Finding[] = result.findings || [];
                console.log("existingFindings = ", existingFindings)
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                console.log("index = ", index)
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
                chrome.storage.local.set({ findings: existingFindings }, () => { });
            });
            break;
        }
    }
}