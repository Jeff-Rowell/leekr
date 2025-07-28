import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectLangsmith } from './langsmith';

export class LangsmithDetector implements SecretDetector {
    readonly type = 'langsmith';
    readonly name = patterns['LangSmith API Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectLangsmith(content, url);
    }
}