import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectPayPalOAuth } from './paypal_oauth';

export class PayPalOAuthDetector implements SecretDetector {
    readonly type = 'paypal_oauth';
    readonly name = patterns['PayPal OAuth Client Secret'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectPayPalOAuth(content, url);
    }
}