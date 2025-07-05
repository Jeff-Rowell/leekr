import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { patterns } from '../../../config/patterns';
import { detectDockerKeys } from './docker';

export class DockerDetector implements SecretDetector {
    readonly type = 'docker';
    readonly name = patterns['Docker Auth Config'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectDockerKeys(content, url);
    }
}