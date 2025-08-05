import { Finding } from "src/types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { validatePayPalOAuthCredentials } from "./paypal_oauth";

export async function paypalOAuthValidityHelper(finding: Finding): Promise<void> {
    for (const paypalOccurrence of Object.values(finding.secretValue)) {
        const validationResult = await validatePayPalOAuthCredentials(
            paypalOccurrence.client_id,
            paypalOccurrence.client_secret
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