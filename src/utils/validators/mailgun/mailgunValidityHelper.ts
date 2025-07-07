import { validateMailgunCredentials } from './mailgun';
import { MailgunValidationResult } from '../../../types/mailgun';
import { Finding } from "../../../types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { patterns } from '../../../config/patterns';

export async function validateMailgunValidity(apiKey: string): Promise<MailgunValidationResult> {
    if (!apiKey || apiKey.trim().length === 0) {
        return {
            valid: false,
            error: 'API key is required'
        };
    }

    const mailgunPatterns = [
        patterns['Mailgun Original Token'].pattern,
        patterns['Mailgun Key Token'].pattern,
        patterns['Mailgun Hex Token'].pattern
    ];

    let isValidFormat = false;
    for (const pattern of mailgunPatterns) {
        const patternSource = pattern.source;
        const exactMatchPattern = new RegExp('^' + patternSource.replace(/\\b/g, '').replace(/[()]/g, '') + '$');
        if (exactMatchPattern.test(apiKey)) {
            isValidFormat = true;
            break;
        }
    }

    if (!isValidFormat) {
        return {
            valid: false,
            error: 'Invalid Mailgun API key format'
        };
    }

    return await validateMailgunCredentials(apiKey);
}

export async function mailgunValidityHelper(finding: Finding): Promise<void> {
    if (!finding.secretValue || typeof finding.secretValue !== 'object') {
        return;
    }

    if ((finding.secretValue as any).apiKey) {
        const mailgunData = finding.secretValue as any;
        const apiKey = mailgunData.apiKey;

        const validationResult = await validateMailgunCredentials(apiKey);

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

    for (const mailgunOccurrence of Object.values(finding.secretValue)) {
        const occurrence = mailgunOccurrence as any;
        
        let mailgunData: any = null;
        
        if (typeof occurrence === 'object' && occurrence !== null && occurrence.match && occurrence.match.apiKey) {
            mailgunData = occurrence.match;
        } else if (typeof occurrence === 'object' && occurrence !== null && occurrence.apiKey) {
            mailgunData = occurrence;
        } else {
            continue;
        }

        const apiKey = mailgunData.apiKey;
        const validationResult = await validateMailgunCredentials(apiKey);

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