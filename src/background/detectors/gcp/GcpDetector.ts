import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectGcpKeys } from './gcp';

export class GcpDetector implements SecretDetector {
    readonly type = 'gcp';
    readonly name = patterns['GCP Service Account Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectGcpKeys(content, url);
    }
}