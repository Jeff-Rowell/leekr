import { Finding } from '../../../types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateArtifactoryCredentials } from './artifactory';

export async function artifactoryValidityHelper(finding: Finding): Promise<void> {
    for (const artifactoryOccurrence of Object.values(finding.secretValue)) {
        if (!artifactoryOccurrence.api_key) {
            continue;
        }

        const validationResult = await validateArtifactoryCredentials(
            artifactoryOccurrence.api_key,
            artifactoryOccurrence.url
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