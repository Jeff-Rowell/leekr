import { SecretDetector } from '../detector.interface';
import { detectApolloKeys } from './apollo';
import { Occurrence } from '../../../types/findings.types';

export class ApolloDetector implements SecretDetector {
    readonly type = 'Apollo';
    readonly name = 'Apollo API Key Detector';

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectApolloKeys(content, url);
    }
}