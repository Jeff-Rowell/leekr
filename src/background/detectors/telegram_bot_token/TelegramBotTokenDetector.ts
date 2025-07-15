import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectTelegramBotTokens } from './telegram_bot_token';

export class TelegramBotTokenDetector implements SecretDetector {
    readonly type = 'telegram_bot_token';
    readonly name = patterns['Telegram Bot Token'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectTelegramBotTokens(content, url);
    }
}