import { patterns } from '../../../config/patterns';
import { Occurrence } from '../../../types/findings.types';
import { SecretDetector } from '../detector.interface';
import { detectGeminiKeys } from './gemini';

export class GeminiDetector implements SecretDetector {
    readonly type = 'gemini';
    readonly name = patterns['Gemini API Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectGeminiKeys(content, url);
    }
}