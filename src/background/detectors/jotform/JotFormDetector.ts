import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectJotFormKeys } from './jotform';

export class JotFormDetector implements SecretDetector {
    readonly type = 'jotform';
    readonly name = patterns['JotForm API Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectJotFormKeys(content, url);
    }
}