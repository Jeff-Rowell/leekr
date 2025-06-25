import { SecretDetector } from '../detector.interface';
import { Occurrence } from '../../../types/findings.types';
import { detectArtifactoryKeys } from './artifactory';
import { patterns } from '../../../config/patterns';

export class ArtifactoryDetector implements SecretDetector {
    readonly name = patterns['Artifactory Access Token'].familyName;
    readonly type = 'Artifactory';

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectArtifactoryKeys(content, url);
    }
}