import { Finding } from "../../../types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { validateDockerCredentials } from "./docker";

export async function dockerValidityHelper(finding: Finding): Promise<void> {
    // Handle direct flat structure (secretValue has registry and auth directly)
    if ((finding.secretValue as any).registry && (finding.secretValue as any).auth) {
        const dockerData = finding.secretValue as any;
        
        // Reconstruct the Docker auth config from the occurrence data
        const authData: any = {
            auth: dockerData.auth
        };
        
        // Only include optional fields if they have values
        if (dockerData.username !== undefined) {
            authData.username = dockerData.username;
        }
        if (dockerData.password !== undefined) {
            authData.password = dockerData.password;
        }
        if (dockerData.email !== undefined) {
            authData.email = dockerData.email;
        }

        const authConfig = JSON.stringify({
            auths: {
                [dockerData.registry]: authData
            }
        });

        const validationResult = await validateDockerCredentials(authConfig);

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
            // Handle situations where the key was deactivated and then re-activated later on
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
            return;
        } else {
            // Is still valid, update the timestamp
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
        }
        
        return;
    }

    // Handle nested structures (multiple occurrences)
    for (const dockerOccurrence of Object.values(finding.secretValue)) {
        const occurrence = dockerOccurrence as any;
        
        // Handle both formats: direct registry/auth or nested match object
        let dockerData: any = null;
        
        // Check if it's a nested match object format
        if (typeof occurrence === 'object' && occurrence.match && occurrence.match.registry && occurrence.match.auth) {
            dockerData = occurrence.match;
        }
        // Check if it's a direct registry/auth format
        else if (typeof occurrence === 'object' && occurrence.registry && occurrence.auth) {
            dockerData = occurrence;
        }
        // Skip if neither format matches or if it's a string field (validity, validatedAt)
        else {
            continue;
        }

        // Reconstruct the Docker auth config from the occurrence data
        const authData: any = {
            auth: dockerData.auth
        };
        
        // Only include optional fields if they have values
        if (dockerData.username !== undefined) {
            authData.username = dockerData.username;
        }
        if (dockerData.password !== undefined) {
            authData.password = dockerData.password;
        }
        if (dockerData.email !== undefined) {
            authData.email = dockerData.email;
        }

        const authConfig = JSON.stringify({
            auths: {
                [dockerData.registry]: authData
            }
        });

        const validationResult = await validateDockerCredentials(authConfig);

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
            // Handle situations where the key was deactivated and then re-activated later on
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
            break;
        } else {
            // Is still valid, update the timestamp
            if (index !== -1) {
                existingFindings[index].validity = "valid";
                existingFindings[index].validatedAt = new Date().toISOString();
            }
            await storeFindings(existingFindings);
        }
        
        // Break after first validation regardless of result
        break;
    }
}