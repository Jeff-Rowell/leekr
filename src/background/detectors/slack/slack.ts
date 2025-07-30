import * as sourceMap from '../../../../external/source-map';
import { SLACK_TOKEN_TYPES } from '../../../config/detectors/slack/slack';
import { patterns } from '../../../config/patterns';
import { SlackOccurrence, SlackSecretValue } from '../../../types/slack';
import { Finding, Occurrence, SourceContent } from '../../../types/findings.types';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';
import { findSecretPosition, getExistingFindings, getSourceMapUrl } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import { validateSlackToken } from '../../../utils/validators/slack/slack';

function getTokenType(token: string): string {
    if (token.startsWith('xoxe.xoxp-')) {
        return SLACK_TOKEN_TYPES['xoxe.xoxp'];
    }
    if (token.startsWith('xoxe-')) {
        return SLACK_TOKEN_TYPES['xoxe'];
    }
    const prefix = token.substring(0, 4);
    return SLACK_TOKEN_TYPES[prefix];
}

export async function detectSlack(content: string, url: string): Promise<Occurrence[]> {
    const botTokenMatches = content.match(patterns['Slack Bot Token'].pattern) || [];
    const userTokenMatches = content.match(patterns['Slack User Token'].pattern) || [];
    const workspaceAccessTokenMatches = content.match(patterns['Slack Workspace Access Token'].pattern) || [];
    const workspaceRefreshTokenMatches = content.match(patterns['Slack Workspace Refresh Token'].pattern) || [];

    const allMatches = [
        ...botTokenMatches,
        ...userTokenMatches,
        ...workspaceAccessTokenMatches,
        ...workspaceRefreshTokenMatches
    ];

    if (allMatches.length === 0) {
        return [];
    }

    const validTokens = allMatches.filter(token => {
        const entropy = calculateShannonEntropy(token);
        const entropyThreshold = patterns["Slack Bot Token"].entropy;
        if (entropy < entropyThreshold) return false;

        const [isFP] = isKnownFalsePositive(token);
        return !isFP;
    });

    if (validTokens.length === 0) {
        return [];
    }

    const existingFindings = await getExistingFindings();
    const filteredTokens = await Promise.all(
        validTokens.map(async (token) => {
            const alreadyFound = existingFindings.some(
                (finding: Finding) => {
                    return Object.values(finding.secretValue).some(
                        (match: SlackSecretValue) => {
                            return Object.values(match).includes(token);
                        }
                    );
                }
            );
            return alreadyFound ? null : token;
        })
    );
    const prunedTokens = filteredTokens.filter((token): token is string => token !== null);

    const validOccurrences: Occurrence[] = [];
    for (const token of prunedTokens) {
        const validationResult = await validateSlackToken(token);
        if (validationResult.valid) {
            const tokenType = getTokenType(token);
            var newSourceContent: SourceContent = {
                content: JSON.stringify({
                    token: token,
                    token_type: tokenType
                }),
                contentFilename: url.split('/').pop() || "",
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            };

            const sourceMapUrl = getSourceMapUrl(url, content);
            if (sourceMapUrl) {
                const sourceMapResponse = await fetch(sourceMapUrl);
                const sourceMapContent = await sourceMapResponse.text();
                sourceMap.SourceMapConsumer.initialize({
                    "lib/mappings.wasm": chrome.runtime.getURL('libs/mappings.wasm'),
                });
                await sourceMap.SourceMapConsumer.with(sourceMapContent, null, (consumer: any) => {
                    const tokenPosition = findSecretPosition(content, token);
                    const originalPosition = consumer.originalPositionFor({
                        line: tokenPosition.line,
                        column: tokenPosition.column
                    });
                    if (originalPosition.source) {
                        const sourceContent = consumer.sourceContentFor(originalPosition.source);
                        newSourceContent = {
                            content: sourceContent,
                            contentFilename: originalPosition.source,
                            contentStartLineNum: originalPosition.line - 5,
                            contentEndLineNum: originalPosition.line + 5,
                            exactMatchNumbers: [originalPosition.line]
                        };
                    }
                });
            }

            const match: SlackOccurrence = {
                secretType: patterns['Slack Bot Token'].familyName,
                fingerprint: "",
                secretValue: {
                    match: {
                        token: token,
                        token_type: tokenType
                    }
                },
                filePath: url.split('/').pop() || "",
                url: url,
                sourceContent: newSourceContent
            };
            match.validity = "valid";
            match.team = validationResult.team;
            match.user = validationResult.user;
            match.teamId = validationResult.teamId;
            match.userId = validationResult.userId;
            match.botId = validationResult.botId;
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