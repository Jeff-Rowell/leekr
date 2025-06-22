import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectOpenAIKeys } from './openai';

export class OpenAIDetector implements SecretDetector {
    readonly type = 'openai';
    readonly name = patterns['OpenAI API Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectOpenAIKeys(content, url);
    }
}