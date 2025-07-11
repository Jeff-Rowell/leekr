import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { detectDeepAIKeys } from './deepai';
import { patterns } from '../../../config/patterns';

export class DeepAIDetector implements SecretDetector {
    readonly name = patterns['DeepAI API Key'].familyName;
    readonly type = 'DeepAI';

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectDeepAIKeys(content, url);
    }
}