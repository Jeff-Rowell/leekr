import { Finding } from "src/types/findings.types";
import { validateAWSCredentials } from "./aws";
import { retrieveFindings, storeFindings } from "../../helpers/common";

export async function awsValidityHelper(finding: Finding): Promise<void> {
    for (const awsOccurrence of Object.values(finding.secretValue)) {
        const validationResult = await validateAWSCredentials(
            awsOccurrence.access_key_id,
            awsOccurrence.secret_key_id
        );
        if (!validationResult.valid) {
            retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                existingFindings[index].validity = "invalid";
                existingFindings[index].validatedAt = new Date().toISOString();
                storeFindings(existingFindings);
            });
            break;
        } else if (finding.validity === 'invalid') {
            // this handles situations where the key was deactivated and then re-activated later on
            retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
                storeFindings(existingFindings);
            });
            break;
        } else {
            // is still valid, update the timstamp
            retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
                storeFindings(existingFindings);
            });
        }
    }
}