import { Finding } from '../../../types/findings.types';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateApolloCredentials } from './apollo';

export async function apolloValidityHelper(finding: Finding): Promise<void> {
    // Extract the API key from the finding structure
    const apolloMatch = (finding.secretValue as any).match;
    if (!apolloMatch || !apolloMatch.api_key) {
        return;
    }

    const validationResult = await validateApolloCredentials(
        apolloMatch.api_key
    );

    // Update the finding based on validation result
    const existingFindings = await retrieveFindings();
    const index = existingFindings.findIndex(
        (f) => f.fingerprint === finding.fingerprint
    );
    
    if (index === -1) {
        return;
    }

    if (!validationResult.valid) {
        existingFindings[index].validity = "invalid";
        existingFindings[index].validatedAt = new Date().toISOString();
    } else {
        existingFindings[index].validity = "valid";
        existingFindings[index].validatedAt = new Date().toISOString();
    }
    
    await storeFindings(existingFindings);
}