import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectAnthropicKeys } from './anthropic';

export class AnthropicDetector implements SecretDetector {
    readonly type = 'anthropic';
    readonly name = patterns['Anthropic API Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectAnthropicKeys(content, url);
    }
}