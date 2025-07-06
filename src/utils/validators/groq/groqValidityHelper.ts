import { validateGroqCredentials } from './groq';
import { GroqValidationResult } from '../../../types/groq';
import { Finding } from "../../../types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { patterns } from '../../../config/patterns';

export async function validateGroqValidity(apiKey: string): Promise<GroqValidationResult> {
    if (!apiKey || apiKey.trim().length === 0) {
        return {
            valid: false,
            error: 'API key is required'
        };
    }

    if (apiKey.length !== 56) {
        return {
            valid: false,
            error: 'Groq API key must be 56 characters'
        };
    }

    // Extract the core pattern from the global pattern and test for exact match
    const groqPattern = patterns['Groq API Key'].pattern;
    const groqPatternSource = groqPattern.source; // "\b(gsk_[a-zA-Z0-9]{52})\b"
    // Extract the capture group content and create an exact match pattern
    const exactMatchPattern = new RegExp('^' + groqPatternSource.replace(/\\b/g, '').replace(/[()]/g, '') + '$');
    
    if (!exactMatchPattern.test(apiKey)) {
        return {
            valid: false,
            error: 'Groq API key must start with gsk_ and contain only alphanumeric characters'
        };
    }

    return await validateGroqCredentials(apiKey);
}

export async function groqValidityHelper(finding: Finding): Promise<void> {
    if (!finding.secretValue || typeof finding.secretValue !== 'object') {
        return;
    }

    if ((finding.secretValue as any).apiKey) {
        const groqData = finding.secretValue as any;
        const apiKey = groqData.apiKey;

        const validationResult = await validateGroqCredentials(apiKey);

        const existingFindings = await retrieveFindings();
        const index = existingFindings.findIndex(
            (f) => f.fingerprint === finding.fingerprint
        );

        if (!validationResult.valid) {
            if (index !== -1) {
                existingFindings[index].validity = "invalid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
            return;
        } else if (finding.validity === 'invalid') {
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
            return;
        } else {
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
        }
        
        return;
    }

    for (const groqOccurrence of Object.values(finding.secretValue)) {
        const occurrence = groqOccurrence as any;
        
        let groqData: any = null;
        
        if (typeof occurrence === 'object' && occurrence !== null && occurrence.match && occurrence.match.apiKey) {
            groqData = occurrence.match;
        } else if (typeof occurrence === 'object' && occurrence !== null && occurrence.apiKey) {
            groqData = occurrence;
        } else {
            continue;
        }

        const apiKey = groqData.apiKey;
        const validationResult = await validateGroqCredentials(apiKey);

        const existingFindings = await retrieveFindings();
        const index = existingFindings.findIndex(
            (f) => f.fingerprint === finding.fingerprint
        );

        if (!validationResult.valid) {
            if (index !== -1) {
                existingFindings[index].validity = "invalid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
            break;
        } else if (finding.validity === 'invalid') {
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
            break;
        } else {
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
        }
        
        break;
    }
}