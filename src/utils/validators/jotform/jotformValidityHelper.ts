import { validateJotFormCredentials } from './jotform';
import { JotFormValidationResult } from '../../../types/jotform';
import { Finding } from "../../../types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";

export async function validateJotFormValidity(apiKey: string): Promise<JotFormValidationResult> {
    if (!apiKey || apiKey.trim().length === 0) {
        return {
            valid: false,
            error: 'API key is required'
        };
    }

    if (apiKey.length !== 32) {
        return {
            valid: false,
            error: 'JotForm API key must be 32 characters'
        };
    }

    if (!/^[0-9A-Za-z]{32}$/.test(apiKey)) {
        return {
            valid: false,
            error: 'JotForm API key must contain only alphanumeric characters'
        };
    }

    return await validateJotFormCredentials(apiKey);
}

export async function jotformValidityHelper(finding: Finding): Promise<void> {
    if ((finding.secretValue as any).apiKey) {
        const jotformData = finding.secretValue as any;
        const apiKey = jotformData.apiKey;

        const validationResult = await validateJotFormCredentials(apiKey);

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

    for (const jotformOccurrence of Object.values(finding.secretValue)) {
        const occurrence = jotformOccurrence as any;
        
        let jotformData: any = null;
        
        if (typeof occurrence === 'object' && occurrence !== null && occurrence.match && occurrence.match.apiKey) {
            jotformData = occurrence.match;
        } else if (typeof occurrence === 'object' && occurrence !== null && occurrence.apiKey) {
            jotformData = occurrence;
        } else {
            continue;
        }

        const apiKey = jotformData.apiKey;
        const validationResult = await validateJotFormCredentials(apiKey);

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