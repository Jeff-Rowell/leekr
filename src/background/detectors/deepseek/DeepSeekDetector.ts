import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { detectDeepSeekKeys } from './deepseek';
import { patterns } from '../../../config/patterns';

export class DeepSeekDetector implements SecretDetector {
    readonly name = patterns['DeepSeek API Key'].familyName;
    readonly type = 'DeepSeek';

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectDeepSeekKeys(content, url);
    }
}

