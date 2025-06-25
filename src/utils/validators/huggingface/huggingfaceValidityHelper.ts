import { Finding, ValidityStatus } from '../../../types/findings.types';
import { HuggingFaceSecretValue } from '../../../types/huggingface';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { validateHuggingFaceCredentials } from './huggingface';

export async function huggingfaceValidityHelper(finding: Finding): Promise<void> {
    try {
        const secretValue = finding.secretValue as HuggingFaceSecretValue;
        const apiKey = secretValue.match.api_key;

        const validationResult = await validateHuggingFaceCredentials(apiKey);
        
        // Retrieve current findings
        const currentFindings = await retrieveFindings();
        
        // Find and update the specific finding
        const updatedFindings = currentFindings.map(f => {
            if (f.fingerprint === finding.fingerprint) {
                return {
                    ...f,
                    validity: (validationResult.valid ? 'valid' : 'invalid') as ValidityStatus,
                    validatedAt: new Date().toISOString(),
                    secretValue: {
                        ...f.secretValue,
                        validity: validationResult.valid ? 'valid' : 'invalid',
                        validatedAt: new Date().toISOString()
                    }
                };
            }
            return f;
        });

        // Store the updated findings
        await storeFindings(updatedFindings);
    } catch (error) {
        console.error('Error in huggingfaceValidityHelper:', error);
        
        // Mark as failed to check on error
        const currentFindings = await retrieveFindings();
        const updatedFindings = currentFindings.map(f => {
            if (f.fingerprint === finding.fingerprint) {
                return {
                    ...f,
                    validity: 'failed_to_check' as ValidityStatus,
                    validatedAt: new Date().toISOString(),
                    secretValue: {
                        ...f.secretValue,
                        validity: 'failed_to_check',
                        validatedAt: new Date().toISOString()
                    }
                };
            }
            return f;
        });
        
        await storeFindings(updatedFindings);
    }
}