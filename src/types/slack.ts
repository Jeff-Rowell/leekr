import { Occurrence } from './findings.types';

export interface SlackSecretValue {
    match: {
        token: string;
        token_type: string;
    };
}

export interface SlackOccurrence extends Occurrence {
    secretValue: SlackSecretValue;
    validity?: string;
    team?: string;
    user?: string;
    teamId?: string;
    userId?: string;
    botId?: string;
}