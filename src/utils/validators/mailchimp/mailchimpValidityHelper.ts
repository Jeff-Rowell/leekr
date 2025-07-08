import { validateMailchimpCredentials } from './mailchimp';
import { MailchimpValidationResult } from '../../../types/mailchimp';
import { Finding } from "../../../types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { patterns } from '../../../config/patterns';

export async function validateMailchimpValidity(apiKey: string): Promise<MailchimpValidationResult> {
    if (!apiKey || apiKey.trim().length === 0) {
        return {
            valid: false,
            error: 'API key is required'
        };
    }

    const mailchimpPattern = patterns['Mailchimp API Key'].pattern;
    const patternSource = mailchimpPattern.source;
    const exactMatchPattern = new RegExp('^' + patternSource.replace(/\\b/g, '').replace(/[()]/g, '') + '$');
    
    if (!exactMatchPattern.test(apiKey)) {
        return {
            valid: false,
            error: 'Invalid Mailchimp API key format'
        };
    }

    return await validateMailchimpCredentials(apiKey);
}

export async function mailchimpValidityHelper(finding: Finding): Promise<void> {
    if (!finding.secretValue || typeof finding.secretValue !== 'object') {
        return;
    }

    if ((finding.secretValue as any).apiKey) {
        const mailchimpData = finding.secretValue as any;
        const apiKey = mailchimpData.apiKey;

        const validationResult = await validateMailchimpCredentials(apiKey);

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

    for (const mailchimpOccurrence of Object.values(finding.secretValue)) {
        const occurrence = mailchimpOccurrence as any;
        
        let mailchimpData: any = null;
        
        if (typeof occurrence === 'object' && occurrence !== null && occurrence.match && occurrence.match.apiKey) {
            mailchimpData = occurrence.match;
        } else if (typeof occurrence === 'object' && occurrence !== null && occurrence.apiKey) {
            mailchimpData = occurrence;
        } else {
            continue;
        }

        const apiKey = mailchimpData.apiKey;
        const validationResult = await validateMailchimpCredentials(apiKey);

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