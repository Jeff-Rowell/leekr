import { ConcreteDetectorFactory } from './DetectorFactory';
import { AwsAccessKeysDetector } from './aws/AwsAccessKeysDetector';
import { AwsSessionKeysDetector } from './aws/AwsSessionKeysDetector';
import { AnthropicDetector } from './anthropic/AnthropicDetector';
import { OpenAIDetector } from './openai/OpenAIDetector';
import { GeminiDetector } from './gemini/GeminiDetector';

describe('ConcreteDetectorFactory', () => {
    let factory: ConcreteDetectorFactory;

    beforeEach(() => {
        factory = new ConcreteDetectorFactory();
    });

    test('createDetectors returns all detector instances', () => {
        const detectors = factory.createDetectors();
        
        expect(detectors).toHaveLength(5);
        expect(detectors[0]).toBeInstanceOf(AwsAccessKeysDetector);
        expect(detectors[1]).toBeInstanceOf(AwsSessionKeysDetector);
        expect(detectors[2]).toBeInstanceOf(AnthropicDetector);
        expect(detectors[3]).toBeInstanceOf(OpenAIDetector);
        expect(detectors[4]).toBeInstanceOf(GeminiDetector);
    });

    test('createDetector returns specific detector by type', () => {
        const awsAccessKeysDetector = factory.createDetector('aws_access_keys');
        const awsSessionKeysDetector = factory.createDetector('aws_session_keys');
        const anthropicDetector = factory.createDetector('anthropic');
        const openaiDetector = factory.createDetector('openai');
        const geminiDetector = factory.createDetector('gemini');

        expect(awsAccessKeysDetector).toBeInstanceOf(AwsAccessKeysDetector);
        expect(awsSessionKeysDetector).toBeInstanceOf(AwsSessionKeysDetector);
        expect(anthropicDetector).toBeInstanceOf(AnthropicDetector);
        expect(openaiDetector).toBeInstanceOf(OpenAIDetector);
        expect(geminiDetector).toBeInstanceOf(GeminiDetector);
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
    });
});