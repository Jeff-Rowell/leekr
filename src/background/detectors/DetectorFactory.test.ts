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

describe('ConcreteDetectorFactory', () => {
    let factory: ConcreteDetectorFactory;

    beforeEach(() => {
        factory = new ConcreteDetectorFactory();
    });

    test('createDetectors returns all detector instances', () => {
        const detectors = factory.createDetectors();
        
        expect(detectors).toHaveLength(14);
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
    });
});