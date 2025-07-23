import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectMakeApiToken } from './make';

export class MakeDetector implements SecretDetector {
    readonly type = 'make';
    readonly name = patterns['Make API Token'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectMakeApiToken(content, url);
    }
}