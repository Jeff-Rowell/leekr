import { Finding } from '../../../types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateGeminiCredentials } from './gemini';

export async function geminiValidityHelper(finding: Finding): Promise<void> {
    for (const geminiOccurrence of Object.values(finding.secretValue)) {
        if (!geminiOccurrence.api_key || !geminiOccurrence.api_secret) {
            continue;
        }
        
        const validationResult = await validateGeminiCredentials(
            geminiOccurrence.api_key,
            geminiOccurrence.api_secret
        );
        
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
            break;
        } else if (finding.validity === 'invalid') {
            // Re-activate if it was previously invalid but now valid
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
            // Update timestamp for still valid keys
            retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                if (index !== -1) {
                    existingFindings[index].validatedAt = new Date().toISOString();
                    storeFindings(existingFindings);
                }
            });
        }
    }
}