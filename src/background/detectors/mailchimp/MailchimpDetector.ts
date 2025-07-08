import { SecretDetector } from '../detector.interface';
import { detectMailchimpKeys } from './mailchimp';
import { Occurrence } from '../../../types/findings.types';

export class MailchimpDetector implements SecretDetector {
    type = 'Mailchimp';
    name = 'Mailchimp';

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectMailchimpKeys(content, url);
    }
}