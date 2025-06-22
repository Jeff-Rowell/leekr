import { Finding } from '../../../types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateOpenAICredentials } from './openai';

export async function openaiValidityHelper(finding: Finding): Promise<void> {
    for (const openaiOccurrence of Object.values(finding.secretValue)) {
        if (!openaiOccurrence.api_key) {
            continue;
        }
        
        const validationResult = await validateOpenAICredentials(
            openaiOccurrence.api_key
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