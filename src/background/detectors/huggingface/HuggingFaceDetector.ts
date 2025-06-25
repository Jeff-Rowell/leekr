import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectHuggingFaceKeys } from './huggingface';

export class HuggingFaceDetector implements SecretDetector {
    readonly type = 'Hugging Face';
    readonly name = patterns['Hugging Face API Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectHuggingFaceKeys(content, url);
    }
}