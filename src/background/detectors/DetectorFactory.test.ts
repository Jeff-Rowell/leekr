import { ConcreteDetectorFactory } from './DetectorFactory';
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
import { MakeDetector } from './make/MakeDetector';

describe('ConcreteDetectorFactory', () => {
    let factory: ConcreteDetectorFactory;

    beforeEach(() => {
        factory = new ConcreteDetectorFactory();
    });

    test('createDetectors returns all detector instances', () => {
        const detectors = factory.createDetectors();
        
        expect(detectors).toHaveLength(20);
        expect(detectors[0]).toBeInstanceOf(AwsAccessKeysDetector);
        expect(detectors[1]).toBeInstanceOf(AwsSessionKeysDetector);
        expect(detectors[2]).toBeInstanceOf(AnthropicDetector);
        expect(detectors[3]).toBeInstanceOf(OpenAIDetector);
        expect(detectors[4]).toBeInstanceOf(GeminiDetector);
        expect(detectors[5]).toBeInstanceOf(HuggingFaceDetector);
        expect(detectors[6]).toBeInstanceOf(ArtifactoryDetector);
        expect(detectors[7]).toBeInstanceOf(AzureOpenAIDetector);
        expect(detectors[8]).toBeInstanceOf(ApolloDetector);
        expect(detectors[9]).toBeInstanceOf(GcpDetector);
        expect(detectors[10]).toBeInstanceOf(DockerDetector);
        expect(detectors[11]).toBeInstanceOf(JotFormDetector);
        expect(detectors[12]).toBeInstanceOf(GroqDetector);
        expect(detectors[13]).toBeInstanceOf(MailgunDetector);
        expect(detectors[14]).toBeInstanceOf(MailchimpDetector);
        expect(detectors[15]).toBeInstanceOf(DeepSeekDetector);
        expect(detectors[16]).toBeInstanceOf(DeepAIDetector);
        expect(detectors[17]).toBeInstanceOf(TelegramBotTokenDetector);
        expect(detectors[18]).toBeInstanceOf(RapidApiDetector);
        expect(detectors[19]).toBeInstanceOf(MakeDetector);
    });

    test('createDetector returns specific detector by type', () => {
        const awsAccessKeysDetector = factory.createDetector('aws_access_keys');
        const awsSessionKeysDetector = factory.createDetector('aws_session_keys');
        const anthropicDetector = factory.createDetector('anthropic');
        const openaiDetector = factory.createDetector('openai');
        const geminiDetector = factory.createDetector('gemini');
        const huggingfaceDetector = factory.createDetector('Hugging Face');
        const artifactoryDetector = factory.createDetector('Artifactory');
        const azureOpenAIDetector = factory.createDetector('Azure OpenAI');
        const apolloDetector = factory.createDetector('Apollo');
        const gcpDetector = factory.createDetector('gcp');
        const dockerDetector = factory.createDetector('docker');
        const jotformDetector = factory.createDetector('jotform');
        const groqDetector = factory.createDetector('Groq');
        const mailgunDetector = factory.createDetector('Mailgun');
        const mailchimpDetector = factory.createDetector('Mailchimp');
        const deepseekDetector = factory.createDetector('DeepSeek');
        const deepaiDetector = factory.createDetector('DeepAI');
        const telegramBotTokenDetector = factory.createDetector('telegram_bot_token');
        const rapidApiDetector = factory.createDetector('rapid_api');
        const makeDetector = factory.createDetector('make');

        expect(awsAccessKeysDetector).toBeInstanceOf(AwsAccessKeysDetector);
        expect(awsSessionKeysDetector).toBeInstanceOf(AwsSessionKeysDetector);
        expect(anthropicDetector).toBeInstanceOf(AnthropicDetector);
        expect(openaiDetector).toBeInstanceOf(OpenAIDetector);
        expect(geminiDetector).toBeInstanceOf(GeminiDetector);
        expect(huggingfaceDetector).toBeInstanceOf(HuggingFaceDetector);
        expect(artifactoryDetector).toBeInstanceOf(ArtifactoryDetector);
        expect(azureOpenAIDetector).toBeInstanceOf(AzureOpenAIDetector);
        expect(apolloDetector).toBeInstanceOf(ApolloDetector);
        expect(gcpDetector).toBeInstanceOf(GcpDetector);
        expect(dockerDetector).toBeInstanceOf(DockerDetector);
        expect(jotformDetector).toBeInstanceOf(JotFormDetector);
        expect(groqDetector).toBeInstanceOf(GroqDetector);
        expect(mailgunDetector).toBeInstanceOf(MailgunDetector);
        expect(mailchimpDetector).toBeInstanceOf(MailchimpDetector);
        expect(deepseekDetector).toBeInstanceOf(DeepSeekDetector);
        expect(deepaiDetector).toBeInstanceOf(DeepAIDetector);
        expect(telegramBotTokenDetector).toBeInstanceOf(TelegramBotTokenDetector);
        expect(rapidApiDetector).toBeInstanceOf(RapidApiDetector);
        expect(makeDetector).toBeInstanceOf(MakeDetector);
    });

    test('createDetector returns undefined for unknown type', () => {
        const unknownDetector = factory.createDetector('unknown_type');
        expect(unknownDetector).toBeUndefined();
    });

    test('detector instances have correct properties', () => {
        const detectors = factory.createDetectors();
        
        const awsAccessKeysDetector = detectors[0];
        expect(awsAccessKeysDetector.type).toBe('aws_access_keys');
        expect(awsAccessKeysDetector.name).toBe('AWS Access & Secret Keys');

        const awsSessionKeysDetector = detectors[1];
        expect(awsSessionKeysDetector.type).toBe('aws_session_keys');
        expect(awsSessionKeysDetector.name).toBe('AWS Session Keys');

        const anthropicDetector = detectors[2];
        expect(anthropicDetector.type).toBe('anthropic');
        expect(anthropicDetector.name).toBe('Anthropic AI');

        const openaiDetector = detectors[3];
        expect(openaiDetector.type).toBe('openai');
        expect(openaiDetector.name).toBe('OpenAI');

        const geminiDetector = detectors[4];
        expect(geminiDetector.type).toBe('gemini');
        expect(geminiDetector.name).toBe('Gemini');

        const huggingfaceDetector = detectors[5];
        expect(huggingfaceDetector.type).toBe('Hugging Face');

        const deepseekDetector = detectors[15];
        expect(deepseekDetector.type).toBe('DeepSeek');
        expect(deepseekDetector.name).toBe('DeepSeek');

        const deepaiDetector = detectors[16];
        expect(deepaiDetector.type).toBe('DeepAI');
        expect(deepaiDetector.name).toBe('DeepAI');

        const telegramBotTokenDetector = detectors[17];
        expect(telegramBotTokenDetector.type).toBe('telegram_bot_token');
        expect(telegramBotTokenDetector.name).toBe('Telegram Bot Token');

        const rapidApiDetector = detectors[18];
        expect(rapidApiDetector.type).toBe('rapid_api');
        expect(rapidApiDetector.name).toBe('RapidAPI');

        const makeDetector = detectors[19];
        expect(makeDetector.type).toBe('make');
        expect(makeDetector.name).toBe('Make');
    });
});