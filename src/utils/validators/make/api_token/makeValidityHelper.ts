import { Finding } from "../../../../types/findings.types";
import { retrieveFindings, storeFindings } from "../../../helpers/common";
import { validateMakeApiToken } from "./make";

export async function makeValidityHelper(finding: Finding): Promise<void> {
    const makeOccurrence = Object.values(finding.secretValue)[0];
    const validationResult = await validateMakeApiToken(makeOccurrence.api_token);
    
    if (!validationResult.valid) {
        retrieveFindings().then((existingFindings) => {
            const index = existingFindings.findIndex(
                (f) => f.fingerprint === finding.fingerprint
            );
            if (index !== -1) {
                existingFindings[index].validity = "invalid";
                existingFindings[index].validatedAt = new Date().toISOString();
                storeFindings(existingFindings);
            }
        });
    } else if (finding.validity === 'invalid') {
        retrieveFindings().then((existingFindings) => {
            const index = existingFindings.findIndex(
                (f) => f.fingerprint === finding.fingerprint
            );
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
                storeFindings(existingFindings);
            }
        });
    } else {
        retrieveFindings().then((existingFindings) => {
            const index = existingFindings.findIndex(
                (f) => f.fingerprint === finding.fingerprint
            );
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
                storeFindings(existingFindings);
            }
        });
    }
}