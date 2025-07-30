import { DetectorFactory, SecretDetector } from './detector.interface';
import { AwsAccessKeysDetector } from './aws/AwsAccessKeysDetector';
import { AwsSessionKeysDetector } from './aws/AwsSessionKeysDetector';
import { AnthropicDetector } from './anthropic/AnthropicDetector';
import { OpenAIDetector } from './openai/OpenAIDetector';
import { GeminiDetector } from './gemini/GeminiDetector';
import { HuggingFaceDetector } from './huggingface/HuggingFaceDetector';
import { ArtifactoryDetector } from './artifactory/ArtifactoryDetector';
import { AzureOpenAIDetector } from './azure_openai/AzureOpenAIDetector';
import { ApolloDetector } from './apollo/ApolloDetector';
import { GcpDetector } from './gcp/GcpDetector';
import { DockerDetector } from './docker/DockerDetector';
import { JotFormDetector } from './jotform/JotFormDetector';
import { GroqDetector } from './groq/GroqDetector';
import { MailgunDetector } from './mailgun/MailgunDetector';
import { MailchimpDetector } from './mailchimp/MailchimpDetector';
import { DeepSeekDetector } from './deepseek/DeepSeekDetector';
import { DeepAIDetector } from './deepai/DeepAIDetector';
import { TelegramBotTokenDetector } from './telegram_bot_token/TelegramBotTokenDetector';
import { RapidApiDetector } from './rapid_api/RapidApiDetector';
import { MakeDetector } from './make/api_token/MakeDetector';
import { MakeMcpDetector } from './make/mcp_token/MakeMcpDetector';
import { LangsmithDetector } from './langsmith/LangsmithDetector';
import { SlackDetector } from './SlackDetector';

export class ConcreteDetectorFactory implements DetectorFactory {
    private readonly detectorClasses = [
        AwsAccessKeysDetector,
        AwsSessionKeysDetector,
        AnthropicDetector,
        OpenAIDetector,
        GeminiDetector,
        HuggingFaceDetector,
        ArtifactoryDetector,
        AzureOpenAIDetector,
        ApolloDetector,
        GcpDetector,
        DockerDetector,
        JotFormDetector,
        GroqDetector,
        MailgunDetector,
        MailchimpDetector,
        DeepSeekDetector,
        DeepAIDetector,
        TelegramBotTokenDetector,
        RapidApiDetector,
        MakeDetector,
        MakeMcpDetector,
        LangsmithDetector,
        SlackDetector
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