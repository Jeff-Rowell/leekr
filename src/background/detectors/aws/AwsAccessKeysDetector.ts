import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectAwsAccessKeys } from './access_keys/access_keys';

export class AwsAccessKeysDetector implements SecretDetector {
    readonly type = 'aws_access_keys';
    readonly name = patterns['AWS Access Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectAwsAccessKeys(content, url);
    }
}