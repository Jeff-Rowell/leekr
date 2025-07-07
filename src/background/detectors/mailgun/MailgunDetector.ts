import { SecretDetector } from '../detector.interface';
import { detectMailgunKeys } from './mailgun';
import { Occurrence } from '../../../types/findings.types';

export class MailgunDetector implements SecretDetector {
    type = 'Mailgun';
    name = 'Mailgun';

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectMailgunKeys(content, url);
    }
}