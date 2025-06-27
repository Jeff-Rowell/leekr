import { Finding } from '../../../types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateAzureOpenAICredentials } from './azure_openai';

export async function azureOpenAIValidityHelper(finding: Finding): Promise<void> {
    for (const azureOpenAIOccurrence of Object.values(finding.secretValue)) {
        if (!azureOpenAIOccurrence.api_key) {
            continue;
        }

        const validationResult = await validateAzureOpenAICredentials(
            azureOpenAIOccurrence.api_key,
            azureOpenAIOccurrence.url
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