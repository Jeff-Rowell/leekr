import { Finding } from "src/types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { validateGcpCredentials } from "./gcp";

export async function gcpValidityHelper(finding: Finding): Promise<void> {
    for (const gcpOccurrence of Object.values(finding.secretValue)) {
        if (!gcpOccurrence.service_account_key) {
            continue;
        }

        const validationResult = await validateGcpCredentials(
            gcpOccurrence.service_account_key
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
            // is still valid, update the timestamp
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