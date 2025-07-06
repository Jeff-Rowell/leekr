import { SecretDetector } from '../detector.interface';
import { detectGroqKeys } from './groq';
import { Occurrence } from '../../../types/findings.types';

export class GroqDetector implements SecretDetector {
    type = 'Groq';
    name = 'Groq API Key Detector';

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectGroqKeys(content, url);
    }
}