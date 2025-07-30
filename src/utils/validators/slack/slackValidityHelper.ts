import { Finding } from "src/types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { validateSlackToken } from "./slack";

export async function slackValidityHelper(finding: Finding): Promise<void> {
    for (const slackOccurrence of Object.values(finding.secretValue)) {
        const validationResult = await validateSlackToken(slackOccurrence.token);
        
        if (!validationResult.valid) {
            await retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                if (index !== -1) {
                    existingFindings[index].validity = "invalid";
                    existingFindings[index].validatedAt = new Date().toISOString();
                    storeFindings(existingFindings);
                }
            });
            break;
        } else if (finding.validity === 'invalid') {
            await retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                if (index !== -1) {
                    existingFindings[index].validity = "valid";
                    existingFindings[index].validatedAt = new Date().toISOString();
                    storeFindings(existingFindings);
                }
            });
            break;
        } else {
            await retrieveFindings().then((existingFindings) => {
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
}