import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectRapidApiKeys } from './rapid_api';

export class RapidApiDetector implements SecretDetector {
    readonly type = 'rapid_api';
    readonly name = patterns['RapidAPI Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectRapidApiKeys(content, url);
    }
}