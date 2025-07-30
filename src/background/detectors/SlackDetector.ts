import { SecretDetector } from './detector.interface';
import { Occurrence } from '../../types/findings.types';
import { patterns } from '../../config/patterns';
import { detectSlack } from './slack/slack';

export class SlackDetector implements SecretDetector {
    readonly type = 'slack';
    readonly name = patterns['Slack Bot Token'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectSlack(content, url);
    }
}