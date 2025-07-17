import { Finding } from "src/types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { validateRapidApiCredentials } from "./rapid_api";

export async function rapidApiValidityHelper(finding: Finding): Promise<void> {
    for (const rapidApiOccurrence of Object.values(finding.secretValue)) {
        if (!rapidApiOccurrence.api_key) {
            continue;
        }

        const validationResult = await validateRapidApiCredentials(
            rapidApiOccurrence.api_key
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