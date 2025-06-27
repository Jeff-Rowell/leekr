import { SecretDetector } from '../detector.interface';
import { detectAzureOpenAIKeys } from './azure_openai';
import { Occurrence } from '../../../types/findings.types';

export class AzureOpenAIDetector implements SecretDetector {
    readonly type = 'Azure OpenAI';
    readonly name = 'Azure OpenAI API Key Detector';

    async detect(content: string, url: string): Promise<Occurrence[]> {
        return await detectAzureOpenAIKeys(content, url);
    }
}