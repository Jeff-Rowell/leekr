import { Finding } from '../../../types/findings.types';
import { validateDeepSeekApiKey } from './deepseek';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { DeepSeekOccurrence } from '../../../types/deepseek';

export async function deepseekValidityHelper(finding: Finding): Promise<void> {
    const deepSeekOccurrence = finding.secretValue as DeepSeekOccurrence['secretValue'];
    
    if (!deepSeekOccurrence.match?.apiKey) {
        console.error('No API key found in finding');
        return;
    }

    const apiKey = deepSeekOccurrence.match.apiKey;
    
    try {
        const validationResult = await validateDeepSeekApiKey(apiKey);
        
        if (!validationResult.valid) {
            const existingFindings = await retrieveFindings();
            const index = existingFindings.findIndex(
                (f) => f.fingerprint === finding.fingerprint
            );
            if (index !== -1) {
                const now = new Date().toISOString();
                existingFindings[index].validity = 'invalid';
                existingFindings[index].validatedAt = now;
                (existingFindings[index].secretValue as any).validity = 'invalid';
                (existingFindings[index].secretValue as any).validatedAt = now;
                await storeFindings(existingFindings);
            }
        } else if (finding.validity === 'invalid') {
            const existingFindings = await retrieveFindings();
            const index = existingFindings.findIndex(
                (f) => f.fingerprint === finding.fingerprint
            );
            if (index !== -1) {
                const now = new Date().toISOString();
                existingFindings[index].validity = 'valid';
                existingFindings[index].validatedAt = now;
                (existingFindings[index].secretValue as any).validity = 'valid';
                (existingFindings[index].secretValue as any).validatedAt = now;
                await storeFindings(existingFindings);
            }
        } else {
            const existingFindings = await retrieveFindings();
            const index = existingFindings.findIndex(
                (f) => f.fingerprint === finding.fingerprint
            );
            if (index !== -1) {
                const now = new Date().toISOString();
                existingFindings[index].validity = 'valid';
                existingFindings[index].validatedAt = now;
                (existingFindings[index].secretValue as any).validity = 'valid';
                (existingFindings[index].secretValue as any).validatedAt = now;
                await storeFindings(existingFindings);
            }
        }
    } catch (error) {
        console.error('Error validating DeepSeek API key:', error);
        
        const existingFindings = await retrieveFindings();
        const index = existingFindings.findIndex(
            (f) => f.fingerprint === finding.fingerprint
        );
        if (index !== -1) {
            const now = new Date().toISOString();
            existingFindings[index].validity = 'failed_to_check';
            existingFindings[index].validatedAt = now;
            (existingFindings[index].secretValue as any).validity = 'failed_to_check';
            (existingFindings[index].secretValue as any).validatedAt = now;
            await storeFindings(existingFindings);
        }
    }
}