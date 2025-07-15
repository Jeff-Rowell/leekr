import * as sourceMap from '../../../../external/source-map';
import { patterns } from '../../../config/patterns';
import { Finding, Occurrence, SourceContent } from "src/types/findings.types";
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { TelegramBotTokenOccurrence, TelegramBotTokenSecretValue } from '../../../types/telegram_bot_token';
import { validateTelegramBotTokenCredentials } from '../../../utils/validators/telegram_bot_token/telegram_bot_token';
import { TELEGRAM_BOT_TOKEN_RESOURCE_TYPES } from '../../../config/detectors/telegram_bot_token/telegram_bot_token';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';

export async function detectTelegramBotTokens(content: string, url: string): Promise<Occurrence[]> {
    const telegramBotTokenMatches = content.match(patterns['Telegram Bot Token'].pattern) || [];

    if (telegramBotTokenMatches.length === 0) {
        return [];
    }

    const uniqueTokens = [...new Set(telegramBotTokenMatches)];

    const existingFindings = await getExistingFindings();
    const filteredTelegramBotTokens = await Promise.all(
        uniqueTokens.map(async (botToken) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    return Object.values(finding.secretValue).some(
                        (match) => {
                            return Object.values(match as TelegramBotTokenSecretValue).includes(botToken);
                        }
                    );
                }
            );
            return alreadyFound ? null : botToken;
        })
    );

    const prunedTelegramBotTokens = filteredTelegramBotTokens.filter((token): token is string => token !== null);
    const validOccurrences: Occurrence[] = [];

    for (const botToken of prunedTelegramBotTokens) {
        const validationResult = await validateTelegramBotTokenCredentials(botToken);
        if (validationResult.valid) {
            var newSourceContent: SourceContent = {
                content: JSON.stringify({
                    bot_token: botToken
                }),
                contentFilename: url.split('/').pop() || "",
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            }
            const sourceMapUrl = getSourceMapUrl(url, content);
            if (sourceMapUrl) {
                const sourceMapResponse = await fetch(sourceMapUrl);
                const sourceMapContent = await sourceMapResponse.text();
                sourceMap.SourceMapConsumer.initialize({
                    "lib/mappings.wasm": chrome.runtime.getURL('libs/mappings.wasm'),
                });
                await sourceMap.SourceMapConsumer.with(sourceMapContent, null, (consumer: any) => {
                    const botTokenPosition = findSecretPosition(content, botToken);
                    const botTokenOriginalPosition = consumer.originalPositionFor({
                        line: botTokenPosition.line,
                        column: botTokenPosition.column
                    });
                    if (botTokenOriginalPosition.source) {
                        const sourceContent = consumer.sourceContentFor(botTokenOriginalPosition.source);
                        newSourceContent = {
                            content: sourceContent,
                            contentFilename: botTokenOriginalPosition.source,
                            contentStartLineNum: botTokenOriginalPosition.line - 5,
                            contentEndLineNum: botTokenOriginalPosition.line + 5,
                            exactMatchNumbers: [botTokenOriginalPosition.line]
                        };
                    }
                });
            }
            const match: TelegramBotTokenOccurrence = {
                secretType: patterns['Telegram Bot Token'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        bot_token: botToken,
                    }
                },
                filePath: url.split('/').pop() || "",
                url: url,
                type: TELEGRAM_BOT_TOKEN_RESOURCE_TYPES[validationResult.type],
                sourceContent: newSourceContent
            };
            match.validity = "valid";
            match.fingerprint = await computeFingerprint(match.secretValue, 'SHA-512');
            validOccurrences.push(match);
        }
    }

    if (validOccurrences.length > 0) {
        return validOccurrences;
    } else {
        return [];
    }
}