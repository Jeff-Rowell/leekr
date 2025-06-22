import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectAwsSessionKeys } from './session_keys/session_keys';

export class AwsSessionKeysDetector implements SecretDetector {
    readonly type = 'aws_session_keys';
    readonly name = patterns['AWS Session Key'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectAwsSessionKeys(content, url);
    }
}