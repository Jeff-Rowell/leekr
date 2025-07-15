import { Finding } from "src/types/findings.types";
import { retrieveFindings, storeFindings } from "../../helpers/common";
import { validateTelegramBotTokenCredentials } from "./telegram_bot_token";

export async function telegramBotTokenValidityHelper(finding: Finding): Promise<void> {
    for (const telegramBotTokenOccurrence of Object.values(finding.secretValue)) {
        if (!telegramBotTokenOccurrence.bot_token) {
            continue;
        }

        const validationResult = await validateTelegramBotTokenCredentials(
            telegramBotTokenOccurrence.bot_token
        );

        if (!validationResult.valid) {
            retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                if (index !== -1) {
                    existingFindings[index].validity = "invalid";
                    existingFindings[index].validatedAt = new Date().toISOString();
                    storeFindings(existingFindings);
                }
            });
            break;
        } else if (finding.validity === 'invalid') {
            retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                if (index !== -1) {
                    existingFindings[index].validity = "valid";
                    existingFindings[index].validatedAt = new Date().toISOString();
                    storeFindings(existingFindings);
                }
            });
            break;
        } else {
            retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === finding.fingerprint
                );
                if (index !== -1) {
                    existingFindings[index].validity = "valid";
                    existingFindings[index].validatedAt = new Date().toISOString();
                    storeFindings(existingFindings);
                }
            });
        }
    }
}