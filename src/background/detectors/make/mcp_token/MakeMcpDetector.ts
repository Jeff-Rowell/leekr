import { SecretDetector } from '../../detector.interface';
import { Occurrence } from '../../../../types/findings.types';
import { patterns } from '../../../../config/patterns';
import { detectMakeMcpToken } from './make';

export class MakeMcpDetector implements SecretDetector {
    readonly type = 'make_mcp';
    readonly name = patterns['Make MCP Token'].familyName;

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectMakeMcpToken(content, url);
    }
}