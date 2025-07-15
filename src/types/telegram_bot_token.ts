import { Occurrence } from './findings.types';

export interface TelegramBotTokenSecretValue {
    match: {
        bot_token: string;
    };
}

export interface TelegramBotTokenOccurrence extends Occurrence {
    secretValue: TelegramBotTokenSecretValue;
    type: string;
    validity?: string;
}