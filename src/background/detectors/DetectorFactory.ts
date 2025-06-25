import { DetectorFactory, SecretDetector } from './detector.interface';
import { AwsAccessKeysDetector } from './aws/AwsAccessKeysDetector';
import { AwsSessionKeysDetector } from './aws/AwsSessionKeysDetector';
import { AnthropicDetector } from './anthropic/AnthropicDetector';
import { OpenAIDetector } from './openai/OpenAIDetector';
import { GeminiDetector } from './gemini/GeminiDetector';
import { HuggingFaceDetector } from './huggingface/HuggingFaceDetector';

export class ConcreteDetectorFactory implements DetectorFactory {
    private readonly detectorClasses = [
        AwsAccessKeysDetector,
        AwsSessionKeysDetector,
        AnthropicDetector,
        OpenAIDetector,
        GeminiDetector,
        HuggingFaceDetector
    ];

    createDetectors(): SecretDetector[] {
        return this.detectorClasses.map(DetectorClass => new DetectorClass());
    }

    createDetector(type: string): SecretDetector | undefined {
        const DetectorClass = this.detectorClasses.find(
            DetectorClass => new DetectorClass().type === type
        );
        return DetectorClass ? new DetectorClass() : undefined;
    }
}