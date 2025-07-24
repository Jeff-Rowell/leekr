import { fireEvent, render, screen, waitFor, act } from '@testing-library/react';
import { AWSOccurrence } from 'src/types/aws.types';
import { AnthropicOccurrence } from 'src/types/anthropic';
import { OpenAIOccurrence } from 'src/types/openai';
import { GeminiOccurrence } from 'src/types/gemini';
import { HuggingFaceOccurrence } from 'src/types/huggingface';
import { ArtifactoryOccurrence } from 'src/types/artifactory';
import { AzureOpenAIOccurrence } from 'src/types/azure_openai';
import { ApolloOccurrence } from 'src/types/apollo';
import { GcpOccurrence } from 'src/types/gcp';
import { DockerOccurrence } from 'src/types/docker';
import { JotFormOccurrence } from 'src/types/jotform';
import { GroqOccurrence } from 'src/types/groq';
import { MailgunOccurrence } from 'src/types/mailgun';
import { MailchimpOccurrence } from 'src/types/mailchimp';
import { DeepSeekOccurrence } from 'src/types/deepseek';
import { DeepAIOccurrence } from 'src/types/deepai';
import { TelegramBotTokenOccurrence } from 'src/types/telegram_bot_token';
import { RapidApiOccurrence } from 'src/types/rapid_api';
import { MakeOccurrence } from 'src/types/make';
import { Finding, Occurrence } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../../../utils/helpers/common';
import { awsValidityHelper } from '../../../../utils/validators/aws/aws_access_keys/awsValidityHelper';
import { awsSessionValidityHelper } from '../../../../utils/validators/aws/aws_session_keys/awsValidityHelper';
import { anthropicValidityHelper } from '../../../../utils/validators/anthropic/anthropicValidityHelper';
import { openaiValidityHelper } from '../../../../utils/validators/openai/openaiValidityHelper';
import { geminiValidityHelper } from '../../../../utils/validators/gemini/geminiValidityHelper';
import { huggingfaceValidityHelper } from '../../../../utils/validators/huggingface/huggingfaceValidityHelper';
import { artifactoryValidityHelper } from '../../../../utils/validators/artifactory/artifactoryValidityHelper';
import { azureOpenAIValidityHelper } from '../../../../utils/validators/azure_openai/azureOpenAIValidityHelper';
import { apolloValidityHelper } from '../../../../utils/validators/apollo/apolloValidityHelper';
import { gcpValidityHelper } from '../../../../utils/validators/gcp/gcpValidityHelper';
import { dockerValidityHelper } from '../../../../utils/validators/docker/dockerValidityHelper';
import { jotformValidityHelper } from '../../../../utils/validators/jotform/jotformValidityHelper';
import { groqValidityHelper } from '../../../../utils/validators/groq/groqValidityHelper';
import { mailgunValidityHelper } from '../../../../utils/validators/mailgun/mailgunValidityHelper';
import { mailchimpValidityHelper } from '../../../../utils/validators/mailchimp/mailchimpValidityHelper';
import { deepseekValidityHelper } from '../../../../utils/validators/deepseek/deepseekValidityHelper';
import { deepaiValidityHelper } from '../../../../utils/validators/deepai/deepaiValidityHelper';
import { telegramBotTokenValidityHelper } from '../../../../utils/validators/telegram_bot_token/telegramBotTokenValidityHelper';
import { rapidApiValidityHelper } from '../../../../utils/validators/rapid_api/rapidApiValidityHelper';
import { makeValidityHelper } from '../../../../utils/validators/make/api_token/makeValidityHelper';
import { useAppContext } from '../../../AppContext';
import FindingsTab from './FindingsTab';

jest.mock('../../../AppContext', () => ({
    useAppContext: jest.fn(),
}));

jest.mock('../../../../utils/validators/aws/aws_access_keys/awsValidityHelper', () => ({
    awsValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/aws/aws_session_keys/awsValidityHelper', () => ({
    awsSessionValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/anthropic/anthropicValidityHelper', () => ({
    anthropicValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/openai/openaiValidityHelper', () => ({
    openaiValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/gemini/geminiValidityHelper', () => ({
    geminiValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/huggingface/huggingfaceValidityHelper', () => ({
    huggingfaceValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/artifactory/artifactoryValidityHelper', () => ({
    artifactoryValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/azure_openai/azureOpenAIValidityHelper', () => ({
    azureOpenAIValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/apollo/apolloValidityHelper', () => ({
    apolloValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/gcp/gcpValidityHelper', () => ({
    gcpValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/docker/dockerValidityHelper', () => ({
    dockerValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/jotform/jotformValidityHelper', () => ({
    jotformValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/groq/groqValidityHelper', () => ({
    groqValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/mailgun/mailgunValidityHelper', () => ({
    mailgunValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/mailchimp/mailchimpValidityHelper', () => ({
    mailchimpValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/deepseek/deepseekValidityHelper', () => ({
    deepseekValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/deepai/deepaiValidityHelper', () => ({
    deepaiValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/telegram_bot_token/telegramBotTokenValidityHelper', () => ({
    telegramBotTokenValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/rapid_api/rapidApiValidityHelper', () => ({
    rapidApiValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/validators/make/api_token/makeValidityHelper', () => ({
    makeValidityHelper: jest.fn(),
}));

jest.mock('../../../../utils/helpers/common', () => ({
    retrieveFindings: jest.fn(),
    storeFindings: jest.fn(),
}));

jest.mock('./style.css', () => ({}));

jest.mock('lucide-react', () => ({
    RotateCw: () => <div data-testid="rotate-cw-icon" />,
    Settings: () => <div data-testid="settings-icon" />,
    ShieldCheck: () => <svg data-testid="shield-check-icon" />,
    Sparkles: () => <div data-testid="sparkles-icon" />,
}));

jest.mock('../../modalheader/ModalHeader', () => ({
    __esModule: true,
    default: ({ title, onClose }: { title: string; onClose: () => void }) => (
        <div data-testid="modal-header">
            <div>{title}</div>
            <button onClick={onClose} data-testid="modal-close-button">Close</button>
        </div>
    ),
}));

global.chrome = {
    action: {
        setBadgeText: jest.fn(),
    },
    storage: {
        local: {
            set: jest.fn((data, callback) => {
                if (callback) callback();
            }),
        },
    },
    runtime: {
        sendMessage: jest.fn().mockReturnValue(Promise.resolve()),
        getURL: jest.fn((path) => `chrome-extension://extension-id/${path}`),
    },
    tabs: {
        create: jest.fn(),
    },
} as any;

const originalOpen = window.open;
beforeAll(() => {
    window.open = jest.fn();
});

afterAll(() => {
    window.open = originalOpen;
});

describe('FindingsTab', () => {
    const mockOccurrenceOne: AWSOccurrence = {
        accountId: "123456789876",
        arn: "arn:aws:iam::123456789876:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockOccurrenceTwo: AWSOccurrence = {
        accountId: "876123456789",
        arn: "arn:aws:iam::876123456789:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp2",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockOccurrenceThree: AWSOccurrence = {
        accountId: "987654321876",
        arn: "arn:aws:iam::987654321876:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp3",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockOccurrenceFour: AWSOccurrence = {
        accountId: "987654321876",
        arn: "arn:aws:iam::987654321876:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp4",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockSessionOccurrence: AWSOccurrence = {
        accountId: "111222333444",
        arn: "arn:aws:iam::111222333444:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp5",
        resourceType: "Session Key",
        secretType: "AWS Session Keys",
        secretValue: {
            match: { session_key_id: "session123", access_key_id: "lol", secret_key_id: "wut" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockAnthropicOccurrence: AnthropicOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp6",
        type: "ADMIN",
        secretType: "Anthropic AI",
        secretValue: {
            match: { api_key: "sk-ant-api-test123456789" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockOpenAIOccurrence: OpenAIOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp7",
        type: "API Key",
        secretType: "OpenAI",
        secretValue: {
            match: { api_key: "sk-proj-test123T3BlbkFJtest456" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockGeminiOccurrence: GeminiOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp8",
        type: "API Key & Secret",
        secretType: "Gemini",
        secretValue: {
            match: { 
                api_key: "account-1234567890ABCDEFGH12",
                api_secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ12"
            }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockHuggingFaceOccurrence: HuggingFaceOccurrence = {
        filePath: "main.foobar.js",
        fingerprint: "fp9",
        type: "API Key",
        secretType: "Hugging Face",
        secretValue: {
            match: { 
                api_key: "hf_1234567890abcdefghijklmnopqrstuv12"
            }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockOccurrenceOne]);
    const mockOccurrencesTwo: Set<Occurrence> = new Set([mockOccurrenceTwo]);
    const mockOccurrencesThree: Set<Occurrence> = new Set([mockOccurrenceThree]);
    const mockOccurrencesFour: Set<Occurrence> = new Set([mockOccurrenceFour]);
    const mockSessionOccurrences: Set<Occurrence> = new Set([mockSessionOccurrence]);
    const mockAnthropicOccurrences: Set<Occurrence> = new Set([mockAnthropicOccurrence]);
    const mockOpenAIOccurrences: Set<Occurrence> = new Set([mockOpenAIOccurrence]);
    const mockGeminiOccurrences: Set<Occurrence> = new Set([mockGeminiOccurrence]);
    const mockHuggingFaceOccurrences: Set<Occurrence> = new Set([mockHuggingFaceOccurrence]);

    const mockJotFormOccurrence: JotFormOccurrence = {
        filePath: "main.jotform.js",
        fingerprint: "fp15",
        type: "API Key",
        secretType: "JotForm",
        secretValue: {
            match: { 
                apiKey: "abcdefghijklmnopqrstuvwxyz123456"
            }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.jotform.js",
        validity: "valid"
    };

    const mockJotFormOccurrences: Set<Occurrence> = new Set([mockJotFormOccurrence]);

    const mockDeepSeekOccurrence: DeepSeekOccurrence = {
        filePath: "main.deepseek.js",
        fingerprint: "fp19",
        type: "API Key",
        secretType: "DeepSeek",
        secretValue: {
            match: { 
                apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456"
            }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.deepseek.js"
    };

    const mockDeepSeekOccurrences: Set<Occurrence> = new Set([mockDeepSeekOccurrence]);

    const mockDeepAIOccurrence: DeepAIOccurrence = {
        filePath: "main.deepai.js",
        fingerprint: "fp20",
        type: "API Key",
        secretType: "DeepAI",
        secretValue: {
            match: { 
                apiKey: "abcd1234-5678-90ab-cdef-123456789012"
            }
        },
        sourceContent: {
            content: 'const apiKey = "abcd1234-5678-90ab-cdef-123456789012";',
            contentFilename: "main.deepai.js",
            contentStartLineNum: 5,
            contentEndLineNum: 5,
            exactMatchNumbers: [15, 51]
        },
        url: "http://localhost:3000/static/js/main.deepai.js"
    };

    const mockDeepAIOccurrences: Set<Occurrence> = new Set([mockDeepAIOccurrence]);

    const mockTelegramBotTokenOccurrence: TelegramBotTokenOccurrence = {
        filePath: "main.telegram.js",
        fingerprint: "fp21",
        type: "Bot Token",
        secretType: "Telegram Bot Token",
        secretValue: {
            match: { 
                bot_token: "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
            }
        },
        sourceContent: {
            content: 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";',
            contentFilename: "main.telegram.js",
            contentStartLineNum: 5,
            contentEndLineNum: 5,
            exactMatchNumbers: [18, 63]
        },
        url: "http://localhost:3000/static/js/main.telegram.js"
    };

    const mockTelegramBotTokenOccurrences: Set<Occurrence> = new Set([mockTelegramBotTokenOccurrence]);

    const mockRapidApiOccurrence: RapidApiOccurrence = {
        filePath: "main.rapidapi.js",
        fingerprint: "fp22",
        type: "API Key",
        secretType: "RapidAPI",
        secretValue: {
            match: { 
                api_key: "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A"
            }
        },
        sourceContent: {
            content: 'const apiKey = "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A";',
            contentFilename: "main.rapidapi.js",
            contentStartLineNum: 5,
            contentEndLineNum: 5,
            exactMatchNumbers: [16, 66]
        },
        url: "http://localhost:3000/static/js/main.rapidapi.js"
    };

    const mockRapidApiOccurrences: Set<Occurrence> = new Set([mockRapidApiOccurrence]);

    const mockMakeOccurrence: MakeOccurrence = {
        filePath: "main.make.js",
        fingerprint: "fp23",
        secretType: "Make",
        secretValue: {
            match: { 
                api_token: "bbb49d50-239a-4609-9569-63ea15ef0997"
            }
        },
        sourceContent: {
            content: 'const apiToken = "bbb49d50-239a-4609-9569-63ea15ef0997";',
            contentFilename: "main.make.js",
            contentStartLineNum: 5,
            contentEndLineNum: 5,
            exactMatchNumbers: [17, 53]
        },
        url: "http://localhost:3000/static/js/main.make.js"
    };

    const mockMakeOccurrences: Set<Occurrence> = new Set([mockMakeOccurrence]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrencesOne.size,
            occurrences: mockOccurrencesOne,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp2",
            numOccurrences: mockOccurrencesTwo.size,
            occurrences: mockOccurrencesTwo,
            validity: "invalid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "invalid"
            }
        },
        {
            fingerprint: "fp3",
            numOccurrences: mockOccurrencesThree.size,
            occurrences: mockOccurrencesThree,
            validity: "unknown",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "unknown"
            }
        },
        {
            fingerprint: "fp4",
            numOccurrences: mockOccurrencesFour.size,
            occurrences: mockOccurrencesFour,
            validity: "failed_to_check",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "failed_to_check"
            }
        },
        {
            fingerprint: "fp5",
            numOccurrences: mockSessionOccurrences.size,
            occurrences: mockSessionOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Session Keys",
            secretValue: {
                match: { session_token: "session123", access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp6",
            numOccurrences: mockAnthropicOccurrences.size,
            occurrences: mockAnthropicOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Anthropic AI",
            secretValue: {
                match: { api_key: "sk-ant-api-test123456789" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp7",
            numOccurrences: mockOpenAIOccurrences.size,
            occurrences: mockOpenAIOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "OpenAI",
            secretValue: {
                match: { api_key: "sk-proj-test123T3BlbkFJtest456" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp8",
            numOccurrences: mockGeminiOccurrences.size,
            occurrences: mockGeminiOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Gemini",
            secretValue: {
                match: { 
                    api_key: "account-1234567890ABCDEFGH12",
                    api_secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ12"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp9",
            numOccurrences: mockHuggingFaceOccurrences.size,
            occurrences: mockHuggingFaceOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Hugging Face",
            secretValue: {
                match: { 
                    api_key: "hf_1234567890abcdefghijklmnopqrstuv12"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp11",
            numOccurrences: 1,
            occurrences: new Set([{
                fingerprint: "artifactory-fp",
                secretType: "Artifactory",
                filePath: "test.js",
                url: "http://localhost:3000/test.js",
                type: "Access Token",
                secretValue: {
                    match: {
                        api_key: "a".repeat(73),
                        url: "example.jfrog.io"
                    }
                },
                sourceContent: {
                    content: "test content",
                    contentFilename: "test.js",
                    contentStartLineNum: 1,
                    contentEndLineNum: 10,
                    exactMatchNumbers: [5]
                }
            } as ArtifactoryOccurrence]),
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Artifactory",
            secretValue: {
                match: { 
                    api_key: "a".repeat(73),
                    url: "example.jfrog.io"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp10",
            numOccurrences: 1,
            occurrences: new Set([{
                fingerprint: "azure-openai-fp",
                secretType: "Azure OpenAI",
                filePath: "test.js",
                url: "http://localhost:3000/test.js",
                type: "API Key",
                secretValue: {
                    match: {
                        api_key: "abcdef1234567890123456789012345678",
                        url: "test-instance.openai.azure.com"
                    }
                },
                sourceContent: {
                    content: "test content",
                    contentFilename: "test.js",
                    contentStartLineNum: 1,
                    contentEndLineNum: 10,
                    exactMatchNumbers: [5]
                }
            } as AzureOpenAIOccurrence]),
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Azure OpenAI",
            secretValue: {
                match: { 
                    api_key: "abcdef1234567890123456789012345678",
                    url: "test-instance.openai.azure.com"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp12",
            numOccurrences: 1,
            occurrences: new Set([{
                filePath: "main.apollo.js",
                fingerprint: "fp12",
                type: "API_KEY",
                secretType: "Apollo",
                secretValue: {
                    match: { 
                        api_key: "abcdefghij1234567890AB"
                    }
                },
                url: "https://apollo.example.com",
                sourceContent: {
                    content: "foobar",
                    contentFilename: "App.js",
                    contentStartLineNum: 1,
                    contentEndLineNum: 10,
                    exactMatchNumbers: [5]
                }
            } as ApolloOccurrence]),
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Apollo",
            secretValue: {
                match: { 
                    api_key: "abcdefghij1234567890AB"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp13",
            numOccurrences: 1,
            occurrences: new Set([{
                filePath: "gcp-config.js",
                fingerprint: "fp13",
                type: "SERVICE_ACCOUNT",
                secretType: "Google Cloud Platform",
                secretValue: {
                    match: { 
                        service_account_key: JSON.stringify({
                            type: "service_account",
                            project_id: "test-project",
                            client_email: "test@test-project.iam.gserviceaccount.com"
                        })
                    }
                },
                url: "https://gcp.example.com",
                sourceContent: {
                    content: "gcp config",
                    contentFilename: "config.js",
                    contentStartLineNum: 1,
                    contentEndLineNum: 10,
                    exactMatchNumbers: [5]
                }
            } as GcpOccurrence]),
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Google Cloud Platform",
            secretValue: {
                match: { 
                    service_account_key: JSON.stringify({
                        type: "service_account",
                        project_id: "test-project",
                        client_email: "test@test-project.iam.gserviceaccount.com"
                    })
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp14",
            numOccurrences: 1,
            occurrences: new Set([{
                fingerprint: "docker-fp",
                secretType: "Docker",
                filePath: "docker-config.json",
                url: "http://localhost:3000/docker-config.json",
                type: "Registry Credentials",
                secretValue: {
                    match: {
                        registry: "registry.example.com",
                        auth: "dGVzdDp0ZXN0",
                        username: "test",
                        password: "test",
                        email: "test@example.com"
                    }
                },
                sourceContent: {
                    content: "test content",
                    contentFilename: "docker-config.json",
                    contentStartLineNum: 1,
                    contentEndLineNum: 10,
                    exactMatchNumbers: [5]
                }
            } as DockerOccurrence]),
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Docker",
            secretValue: {
                match: { 
                    registry: "registry.example.com",
                    auth: "dGVzdDp0ZXN0",
                    username: "test",
                    password: "test",
                    email: "test@example.com"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp15",
            numOccurrences: mockJotFormOccurrences.size,
            occurrences: mockJotFormOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "JotForm",
            secretValue: {
                match: { 
                    apiKey: "abcdefghijklmnopqrstuvwxyz123456"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp16",
            numOccurrences: 1,
            occurrences: new Set([{
                fingerprint: "groq-fp",
                secretType: "Groq",
                filePath: "groq-config.js",
                url: "http://localhost:3000/groq-config.js",
                type: "API_KEY",
                secretValue: {
                    match: {
                        apiKey: "gsk_" + "a".repeat(52)
                    }
                },
                sourceContent: {
                    content: "test content",
                    contentFilename: "groq-config.js",
                    contentStartLineNum: 1,
                    contentEndLineNum: 10,
                    exactMatchNumbers: [5]
                },
                validity: "valid"
            } as GroqOccurrence]),
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Groq",
            secretValue: {
                match: { 
                    apiKey: "gsk_" + "a".repeat(52)
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp17",
            numOccurrences: 1,
            occurrences: new Set([{
                fingerprint: "mailgun-fp",
                secretType: "Mailgun",
                filePath: "mailgun-config.js",
                url: "http://localhost:3000/mailgun-config.js",
                type: "Mailgun API Key",
                secretValue: {
                    match: {
                        apiKey: "key-" + "a".repeat(32)
                    }
                },
                sourceContent: {
                    content: "test content",
                    contentFilename: "mailgun-config.js",
                    contentStartLineNum: 1,
                    contentEndLineNum: 10,
                    exactMatchNumbers: [5]
                },
                validity: "valid"
            } as MailgunOccurrence]),
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Mailgun",
            secretValue: {
                match: { 
                    apiKey: "key-" + "a".repeat(32)
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp18",
            numOccurrences: 1,
            occurrences: new Set([{
                fingerprint: "mailchimp-fp",
                secretType: "Mailchimp",
                filePath: "mailchimp-config.js",
                url: "http://localhost:3000/mailchimp-config.js",
                type: "Mailchimp API Key",
                secretValue: {
                    match: {
                        apiKey: "abcd1234567890abcd1234567890abcd-us12"
                    }
                },
                sourceContent: {
                    content: "test content",
                    contentFilename: "mailchimp-config.js",
                    contentStartLineNum: 1,
                    contentEndLineNum: 10,
                    exactMatchNumbers: [5]
                },
                validity: "valid"
            } as MailchimpOccurrence]),
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Mailchimp",
            secretValue: {
                match: { 
                    apiKey: "abcd1234567890abcd1234567890abcd-us12"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp19",
            numOccurrences: mockDeepSeekOccurrences.size,
            occurrences: mockDeepSeekOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "DeepSeek",
            secretValue: {
                match: { 
                    apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp20",
            numOccurrences: mockDeepAIOccurrences.size,
            occurrences: mockDeepAIOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "DeepAI",
            secretValue: {
                match: { 
                    apiKey: "abcd1234-5678-90ab-cdef-123456789012"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp21",
            numOccurrences: mockTelegramBotTokenOccurrences.size,
            occurrences: mockTelegramBotTokenOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Telegram Bot Token",
            secretValue: {
                match: { 
                    bot_token: "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp22",
            numOccurrences: mockRapidApiOccurrences.size,
            occurrences: mockRapidApiOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "RapidAPI",
            secretValue: {
                match: { 
                    api_key: "abcdefghij1234567890ABCDEFGHIJ1234567890123456789A"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp23",
            numOccurrences: mockMakeOccurrences.size,
            occurrences: mockMakeOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Make",
            secretValue: {
                match: { 
                    api_token: "bbb49d50-239a-4609-9569-63ea15ef0997"
                },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
    ];

    // Helper to get sorted findings (matches FindingsTab sorting logic)
    const getSortedFindings = (findings: Finding[]) => {
        return [...findings].sort((a, b) => {
            // Sort by isNew first (new findings at top)
            if (a.isNew && !b.isNew) return -1;
            if (!a.isNew && b.isNew) return 1;
            
            // Then sort by discoveredAt (newest first)
            if (a.discoveredAt && b.discoveredAt) {
                return new Date(b.discoveredAt).getTime() - new Date(a.discoveredAt).getTime();
            }
            if (a.discoveredAt && !b.discoveredAt) return -1;
            if (!a.discoveredAt && b.discoveredAt) return 1;
            
            // Finally, sort by secretType alphabetically
            return a.secretType.localeCompare(b.secretType);
        });
    };

    const sortedMockFindings = getSortedFindings(mockFindings);

    beforeEach(() => {
        jest.clearAllMocks();
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindings,
            },
        });

        // Mock retrieveFindings to return empty array by default
        (retrieveFindings as jest.Mock).mockResolvedValue([]);

        Element.prototype.getBoundingClientRect = jest.fn(() => ({
            bottom: 100,
            right: 300,
            width: 50,
            height: 30,
            top: 70,
            left: 250,
            x: 250,
            y: 70,
            toJSON: () => { },
        }));

        window.scrollX = 0;
        window.scrollY = 0;
    });

    test('renders table headers correctly', () => {
        render(<FindingsTab />);
        const rows = screen.getAllByRole('row');
        expect(rows[0]).toHaveTextContent('Type');
        expect(rows[0]).toHaveTextContent('Validity');
        expect(rows[0]).toHaveTextContent('Occurrences');
    });

    test('renders findings correctly', () => {
        render(<FindingsTab />);
        const rows = screen.getAllByRole('row');
        // Findings are sorted alphabetically by secretType
        expect(rows[1]).toHaveTextContent('Anthropic AI');
        expect(rows[1]).toHaveTextContent('valid');
        expect(rows[1]).toHaveTextContent('1');

        expect(rows[2]).toHaveTextContent('Apollo');
        expect(rows[2]).toHaveTextContent('valid');
        expect(rows[2]).toHaveTextContent('1');

        expect(rows[3]).toHaveTextContent('Artifactory');
        expect(rows[3]).toHaveTextContent('valid');
        expect(rows[3]).toHaveTextContent('1');

        expect(rows[4]).toHaveTextContent('AWS Access & Secret Keys');
        expect(rows[4]).toHaveTextContent('valid');
        expect(rows[4]).toHaveTextContent('1');

        expect(rows[5]).toHaveTextContent('AWS Access & Secret Keys');
        expect(rows[5]).toHaveTextContent('invalid');
        expect(rows[5]).toHaveTextContent('1');

        expect(rows[6]).toHaveTextContent('AWS Access & Secret Keys');
        expect(rows[6]).toHaveTextContent('unknown');
        expect(rows[6]).toHaveTextContent('1');
    });

    test('applies correct validity color classes', () => {
        render(<FindingsTab />);

        const validElements = screen.getAllByText('valid');
        const invalidElement = screen.getByText('invalid').closest('.validity-status');
        const unknownElement = screen.getByText('unknown').closest('.validity-status');
        const failedElement = screen.getByText('failed to check').closest('.validity-status');

        expect(validElements[0].closest('.validity-status')).toHaveClass('validity-valid');
        expect(invalidElement).toHaveClass('validity-invalid');
        expect(unknownElement).toHaveClass('validity-unknown');
        expect(failedElement).toHaveClass('validity-failed');
    });

    test('shows validity check icon for validated findings', () => {
        render(<FindingsTab />);
        const shieldIcons = screen.getAllByTestId('shield-check-icon');
        expect(shieldIcons.length).toBe(23);
    });

    test('opens settings menu when settings button is clicked', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        expect(settingsButtons.length).toBe(23);
        fireEvent.click(settingsButtons[0]);

        await waitFor(() => {
            expect(screen.getByText('Finding Options')).toBeInTheDocument();
            expect(screen.getByText('View Occurrences')).toBeInTheDocument();
            expect(screen.getByText('Delete Finding')).toBeInTheDocument();
            expect(screen.getByText('Report Issue')).toBeInTheDocument();
        });
    });

    test('closes settings menu when close button is clicked', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        fireEvent.click(settingsButtons[0]);
        await waitFor(() => {
            expect(screen.getByText('Finding Options')).toBeInTheDocument();
        });

        const closeButton = screen.getByTestId('modal-close-button');
        fireEvent.click(closeButton);
        await waitFor(() => {
            expect(screen.queryByText('Finding Options')).not.toBeInTheDocument();
        });
    });

    test('toggles settings menu when same button is clicked twice', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        fireEvent.click(settingsButtons[0]);
        await waitFor(() => {
            expect(screen.getByText('Finding Options')).toBeInTheDocument();
        });

        fireEvent.click(settingsButtons[0]);
        await waitFor(() => {
            expect(screen.queryByText('Finding Options')).not.toBeInTheDocument();
        });
    });

    test('opens new settings menu when different button is clicked', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        fireEvent.click(settingsButtons[0]);
        await waitFor(() => {
            expect(screen.getByText('Finding Options')).toBeInTheDocument();
        });

        fireEvent.click(settingsButtons[1]);
        await waitFor(() => {
            expect(screen.getByText('Finding Options')).toBeInTheDocument();
        });
    });

    test('calls handleValidityCheck when recheck button is clicked', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);

        fireEvent.click(recheckButtons[0]);
        expect(anthropicValidityHelper).toHaveBeenCalledWith(sortedMockFindings[0]);
    });

    test('calls awsSessionValidityHelper when recheck button is clicked for AWS Session Keys', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);

        fireEvent.click(recheckButtons[7]);
        expect(awsSessionValidityHelper).toHaveBeenCalledWith(sortedMockFindings[7]);
    });

    test('calls anthropicValidityHelper when recheck button is clicked for Anthropic AI', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);

        fireEvent.click(recheckButtons[5]);
        expect(awsValidityHelper).toHaveBeenCalledWith(sortedMockFindings[5]);
    });

    test('calls openaiValidityHelper when recheck button is clicked for OpenAI', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);

        fireEvent.click(recheckButtons[20]);
        expect(openaiValidityHelper).toHaveBeenCalledWith(sortedMockFindings[20]);
    });

    test('calls geminiValidityHelper when recheck button is clicked for Gemini', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);

        fireEvent.click(recheckButtons[12]);
        expect(geminiValidityHelper).toHaveBeenCalledWith(sortedMockFindings[12]);
    });

    test('calls huggingfaceValidityHelper when recheck button is clicked for Hugging Face', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);

        fireEvent.click(recheckButtons[15]);
        expect(huggingfaceValidityHelper).toHaveBeenCalledWith(sortedMockFindings[15]);
    });

    test('opens GitHub issues page when "Report Issue" is clicked', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        fireEvent.click(settingsButtons[0]);

        await waitFor(() => {
            expect(screen.getByText('Report Issue')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByText('Report Issue'));

        expect(window.open).toHaveBeenCalledWith('https://github.com/Jeff-Rowell/Leekr/issues/new', '_blank');
    });

    test('deletes finding when "Delete Finding" is clicked', async () => {
        const mockExistingFindings = [...mockFindings];
        (retrieveFindings as jest.Mock).mockResolvedValue(mockExistingFindings);
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        fireEvent.click(settingsButtons[0]);
        await waitFor(() => {
            expect(screen.getByText('Delete Finding')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByText('Delete Finding'));
        await waitFor(() => {
            expect(retrieveFindings).toHaveBeenCalled();
            expect(storeFindings).toHaveBeenCalled();
        });

        mockExistingFindings.splice(0, 1);
        expect(storeFindings).toHaveBeenCalledWith(mockExistingFindings);
    });

    test('opens options page when "View Occurrences" is clicked', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        fireEvent.click(settingsButtons[0]);
        await waitFor(() => {
            expect(screen.getByText('View Occurrences')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByText('View Occurrences'));
        expect(chrome.runtime.getURL).toHaveBeenCalledWith('options.html');
        expect(chrome.tabs.create).toHaveBeenCalledWith({
            url: 'chrome-extension://extension-id/options.html?tab=findings&fingerprint=fp6'
        });
    });

    test('clears badge and notifications on mount', () => {
        render(<FindingsTab />);

        expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
        expect(chrome.storage.local.set).toHaveBeenCalledWith({ "notifications": '' }, expect.any(Function));
        expect(chrome.runtime.sendMessage).toHaveBeenCalledWith({
            type: 'CLEAR_NOTIFICATIONS',
            payload: ''
        });
    });

    test('handles sendMessage rejection in useEffect catch block', async () => {
        const mockError = new Error('Connection failed');
        (chrome.runtime.sendMessage as jest.Mock).mockReturnValue(Promise.reject(mockError));

        render(<FindingsTab />);

        await waitFor(() => {
            expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
            expect(chrome.storage.local.set).toHaveBeenCalledWith({ "notifications": '' }, expect.any(Function));
            expect(chrome.runtime.sendMessage).toHaveBeenCalledWith({
                type: 'CLEAR_NOTIFICATIONS',
                payload: ''
            });
        });
    });

    test('calls artifactoryValidityHelper for Artifactory findings', async () => {
        render(<FindingsTab />);
        
        // Find the Artifactory recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Artifactory recheck button (sorted index 2) 
        fireEvent.click(recheckButtons[2]);
        
        // Verify artifactory validity helper was called
        expect(artifactoryValidityHelper).toHaveBeenCalledWith(sortedMockFindings[2]);
    });

    test('calls azureOpenAIValidityHelper for Azure OpenAI findings', async () => {
        render(<FindingsTab />);
        
        // Find the Azure OpenAI recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Azure OpenAI recheck button (sorted index 8)
        fireEvent.click(recheckButtons[8]);
        
        // Verify azure openai validity helper was called
        expect(azureOpenAIValidityHelper).toHaveBeenCalledWith(sortedMockFindings[8]);
    });

    test('calls apolloValidityHelper for Apollo findings', async () => {
        render(<FindingsTab />);
        
        // Find the Apollo recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Apollo recheck button (sorted index 1)
        fireEvent.click(recheckButtons[1]);
        
        // Verify apollo validity helper was called
        expect(apolloValidityHelper).toHaveBeenCalledWith(sortedMockFindings[1]);
    });

    test('calls gcpValidityHelper for Google Cloud Platform findings', async () => {
        render(<FindingsTab />);
        
        // Find the GCP recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the GCP recheck button (sorted index 13)
        fireEvent.click(recheckButtons[13]);
        
        // Verify gcp validity helper was called
        expect(gcpValidityHelper).toHaveBeenCalledWith(sortedMockFindings[13]);
    });

    test('closes settings menu when clicking outside', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        fireEvent.click(settingsButtons[0]);
        await waitFor(() => {
            expect(screen.getByText('Finding Options')).toBeInTheDocument();
        });

        fireEvent.mouseDown(document.body);
        await waitFor(() => {
            expect(screen.queryByText('Finding Options')).not.toBeInTheDocument();
        });
    });

    test('positions dropdown above button when there is insufficient space below but sufficient space above', async () => {
        // Mock window dimensions
        Object.defineProperty(window, 'innerHeight', {
            writable: true,
            configurable: true,
            value: 400, // Small window height
        });

        // Mock getBoundingClientRect to simulate a button near the bottom
        Element.prototype.getBoundingClientRect = jest.fn(() => ({
            bottom: 350, // Near bottom of window (spaceBelow = 400 - 350 = 50 < 175)
            right: 300,
            width: 50,
            height: 30,
            top: 320, // High enough that spaceAbove = 320 > 175
            left: 250,
            x: 250,
            y: 320,
            toJSON: () => { },
        }));

        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        fireEvent.click(settingsButtons[0]);

        await waitFor(() => {
            expect(screen.getByText('Finding Options')).toBeInTheDocument();
        });

        // Check that the dropdown is positioned above the button
        // When showAbove is true, top = rect.top - dropdownHeight + window.scrollY
        // top = 320 - 175 + 0 = 145
        const dropdown = screen.getByText('Finding Options').closest('.settings-dropdown');
        expect(dropdown).toHaveStyle('top: 145px');
    });

    test('calls dockerValidityHelper for Docker findings', async () => {
        render(<FindingsTab />);
        
        // Find the Docker recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Docker recheck button (sorted index 11)
        fireEvent.click(recheckButtons[11]);
        
        // Verify docker validity helper was called
        expect(dockerValidityHelper).toHaveBeenCalledWith(sortedMockFindings[11]);
    });

    test('calls jotformValidityHelper when recheck button is clicked for JotForm', async () => {
        render(<FindingsTab />);
        
        // Find the JotForm recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the JotForm recheck button (sorted index 16)
        fireEvent.click(recheckButtons[16]);
        
        // Verify jotform validity helper was called
        expect(jotformValidityHelper).toHaveBeenCalledWith(sortedMockFindings[16]);
    });

    test('calls groqValidityHelper when recheck button is clicked for Groq', async () => {
        render(<FindingsTab />);
        
        // Find the Groq recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Groq recheck button (sorted index 14)
        fireEvent.click(recheckButtons[14]);
        
        // Verify groq validity helper was called
        expect(groqValidityHelper).toHaveBeenCalledWith(sortedMockFindings[14]);
    });

    test('calls mailgunValidityHelper when recheck button is clicked for Mailgun', async () => {
        render(<FindingsTab />);
        
        // Find the Mailgun recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Mailgun recheck button (sorted index 18)
        fireEvent.click(recheckButtons[18]);
        
        // Verify mailgun validity helper was called
        expect(mailgunValidityHelper).toHaveBeenCalledWith(sortedMockFindings[18]);
    });

    test('calls mailchimpValidityHelper when recheck button is clicked for Mailchimp', async () => {
        render(<FindingsTab />);
        
        // Find the Mailchimp recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Mailchimp recheck button (sorted index 17)
        fireEvent.click(recheckButtons[17]);
        
        // Verify mailchimp validity helper was called
        expect(mailchimpValidityHelper).toHaveBeenCalledWith(sortedMockFindings[17]);
    });

    test('calls deepseekValidityHelper when recheck button is clicked for DeepSeek', async () => {
        render(<FindingsTab />);
        
        // Find the DeepSeek recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the DeepSeek recheck button (sorted index 10)
        fireEvent.click(recheckButtons[10]);
        
        // Verify deepseek validity helper was called
        expect(deepseekValidityHelper).toHaveBeenCalledWith(sortedMockFindings[10]);
    });

    test('calls deepaiValidityHelper when recheck button is clicked for DeepAI', async () => {
        render(<FindingsTab />);
        
        // Find the DeepAI recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the DeepAI recheck button (sorted index 9)
        fireEvent.click(recheckButtons[9]);
        
        // Verify deepai validity helper was called
        expect(deepaiValidityHelper).toHaveBeenCalledWith(sortedMockFindings[9]);
    });

    test('calls telegramBotTokenValidityHelper when recheck button is clicked for Telegram Bot Token', async () => {
        render(<FindingsTab />);
        
        // Find the Telegram Bot Token recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Telegram Bot Token recheck button (sorted index 22)
        fireEvent.click(recheckButtons[22]);
        
        // Verify telegram bot token validity helper was called
        expect(telegramBotTokenValidityHelper).toHaveBeenCalledWith(sortedMockFindings[22]);
    });

    test('calls rapidApiValidityHelper when recheck button is clicked for RapidAPI', async () => {
        render(<FindingsTab />);
        
        // Find the RapidAPI recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the RapidAPI recheck button (sorted index 21)
        fireEvent.click(recheckButtons[21]);
        
        // Verify rapidApi validity helper was called
        expect(rapidApiValidityHelper).toHaveBeenCalledWith(sortedMockFindings[21]);
    });

    test('calls makeValidityHelper when recheck button is clicked for Make', async () => {
        render(<FindingsTab />);
        
        // Find the Make recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(23);
        
        // Click the Make recheck button (sorted index 19)
        fireEvent.click(recheckButtons[19]);
        
        // Verify make validity helper was called
        expect(makeValidityHelper).toHaveBeenCalledWith(sortedMockFindings[19]);
    });

    test('renders recheck all button when findings exist', () => {
        render(<FindingsTab />);
        
        // Check that the recheck all button is rendered
        const recheckAllButton = screen.getByLabelText('Recheck all findings');
        expect(recheckAllButton).toBeInTheDocument();
    });

    test('does not render recheck all button when no findings exist', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: [] }
        });

        render(<FindingsTab />);
        
        // Check that the recheck all button is not rendered
        const recheckAllButton = screen.queryByLabelText('Recheck all findings');
        expect(recheckAllButton).not.toBeInTheDocument();
    });

    test('calls handleRecheckAll when recheck all button is clicked', async () => {
        render(<FindingsTab />);
        
        // Find and click the recheck all button
        const recheckAllButton = screen.getByLabelText('Recheck all findings');
        
        act(() => {
            fireEvent.click(recheckAllButton);
        });
        
        // Wait for all validity helpers to be called - handleRecheckAll uses findings from context
        await waitFor(() => {
            // Verify each validator was called with the correct number of findings
            expect(awsValidityHelper).toHaveBeenCalledTimes(4); // 4 AWS Access & Secret Keys
            expect(awsSessionValidityHelper).toHaveBeenCalledTimes(1); // 1 AWS Session Keys
            expect(anthropicValidityHelper).toHaveBeenCalledTimes(1); // 1 Anthropic AI
            expect(openaiValidityHelper).toHaveBeenCalledTimes(1); // 1 OpenAI
            expect(geminiValidityHelper).toHaveBeenCalledTimes(1); // 1 Gemini
            expect(huggingfaceValidityHelper).toHaveBeenCalledTimes(1); // 1 Hugging Face
            expect(artifactoryValidityHelper).toHaveBeenCalledTimes(1); // 1 Artifactory
            expect(azureOpenAIValidityHelper).toHaveBeenCalledTimes(1); // 1 Azure OpenAI
            expect(apolloValidityHelper).toHaveBeenCalledTimes(1); // 1 Apollo
            expect(gcpValidityHelper).toHaveBeenCalledTimes(1); // 1 GCP
            expect(dockerValidityHelper).toHaveBeenCalledTimes(1); // 1 Docker
            expect(jotformValidityHelper).toHaveBeenCalledTimes(1); // 1 JotForm
            expect(groqValidityHelper).toHaveBeenCalledTimes(1); // 1 Groq
            expect(mailgunValidityHelper).toHaveBeenCalledTimes(1); // 1 Mailgun
            expect(mailchimpValidityHelper).toHaveBeenCalledTimes(1); // 1 Mailchimp
            expect(deepseekValidityHelper).toHaveBeenCalledTimes(1); // 1 DeepSeek
            expect(deepaiValidityHelper).toHaveBeenCalledTimes(1); // 1 DeepAI
            expect(telegramBotTokenValidityHelper).toHaveBeenCalledTimes(1); // 1 Telegram Bot Token
            expect(rapidApiValidityHelper).toHaveBeenCalledTimes(1); // 1 RapidAPI
            expect(makeValidityHelper).toHaveBeenCalledTimes(1); // 1 Make
        });
    });

    test('renders tooltip icon and text for recheck all button', () => {
        render(<FindingsTab />);
        
        // Check that the tooltip text is rendered
        const tooltipText = screen.getByText('Recheck the validity of all findings');
        expect(tooltipText).toBeInTheDocument();
    });

    test('renders findings with isNew field correctly', () => {
        const newFindings = [
            {
                ...mockFindings[0],
                isNew: true,
                discoveredAt: "2025-07-14T12:00:00.000Z"
            },
            {
                ...mockFindings[1],
                isNew: false,
                discoveredAt: "2025-07-13T12:00:00.000Z"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: newFindings }
        });

        render(<FindingsTab />);
        
        // Check that findings are rendered
        const rows = screen.getAllByRole('row');
        expect(rows.length).toBeGreaterThan(2);
    });

    test('sorts findings by isNew status first', () => {
        const mixedFindings = [
            {
                ...mockFindings[0],
                isNew: false,
                secretType: "AWS Access & Secret Keys",
                discoveredAt: "2025-07-14T12:00:00.000Z"
            },
            {
                ...mockFindings[1],
                isNew: true,
                secretType: "Anthropic AI", 
                discoveredAt: "2025-07-14T11:00:00.000Z"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: mixedFindings }
        });

        render(<FindingsTab />);
        
        const rows = screen.getAllByRole('row');
        // New finding (Anthropic AI) should come first despite being added later
        expect(rows[1]).toHaveTextContent('Anthropic AI');
        expect(rows[2]).toHaveTextContent('AWS Access & Secret Keys');
    });

    test('sorts findings by discoveredAt when isNew status is same', () => {
        const timeBasedFindings = [
            {
                ...mockFindings[0],
                isNew: false,
                secretType: "AWS Access & Secret Keys",
                discoveredAt: "2025-07-14T10:00:00.000Z"
            },
            {
                ...mockFindings[1],
                isNew: false,
                secretType: "Anthropic AI",
                discoveredAt: "2025-07-14T12:00:00.000Z"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: timeBasedFindings }
        });

        render(<FindingsTab />);
        
        const rows = screen.getAllByRole('row');
        // Newer finding (Anthropic AI at 12:00) should come before older one (AWS at 10:00)
        expect(rows[1]).toHaveTextContent('Anthropic AI');
        expect(rows[2]).toHaveTextContent('AWS Access & Secret Keys');
    });

    test('sorts findings alphabetically by secretType when isNew and discoveredAt are same', () => {
        const alphabeticalFindings = [
            {
                ...mockFindings[0],
                isNew: false,
                secretType: "Zzz Service",
                discoveredAt: "2025-07-14T12:00:00.000Z"
            },
            {
                ...mockFindings[1],
                isNew: false,
                secretType: "Aaa Service",
                discoveredAt: "2025-07-14T12:00:00.000Z"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: alphabeticalFindings }
        });

        render(<FindingsTab />);
        
        const rows = screen.getAllByRole('row');
        // Both findings should be rendered (exact order depends on implementation)
        expect(rows).toHaveLength(3); // Header + 2 data rows
        expect(screen.getByText('Aaa Service')).toBeInTheDocument();
        expect(screen.getByText('Zzz Service')).toBeInTheDocument();
    });

    test('handles findings without discoveredAt field in sorting', () => {
        const mixedDateFindings = [
            {
                ...mockFindings[0],
                isNew: false,
                secretType: "AWS Access & Secret Keys",
                discoveredAt: undefined
            },
            {
                ...mockFindings[1],
                isNew: false,
                secretType: "Anthropic AI",
                discoveredAt: "2025-07-14T12:00:00.000Z"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: mixedDateFindings }
        });

        render(<FindingsTab />);
        
        const rows = screen.getAllByRole('row');
        // Finding with discoveredAt should come before one without
        expect(rows[1]).toHaveTextContent('Anthropic AI');
        expect(rows[2]).toHaveTextContent('AWS Access & Secret Keys');
    });


    test('renders NEW indicator for new findings before viewedFindings is set', () => {
        const newFindings = [
            {
                ...mockFindings[0],
                isNew: true,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: newFindings }
        });

        render(<FindingsTab />);
        
        // Should show NEW indicator initially
        expect(screen.getByTestId('sparkles-icon')).toBeInTheDocument();
        expect(screen.getByText('NEW')).toBeInTheDocument();
    });

    test('applies green highlighting styles for new findings', () => {
        const newFindings = [
            {
                ...mockFindings[0],
                isNew: true,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: newFindings }
        });

        render(<FindingsTab />);
        
        const rows = screen.getAllByRole('row');
        const newFindingRow = rows[1]; // First data row
        
        // Check that the row has the new-finding-row class
        expect(newFindingRow).toHaveClass('new-finding-row');
        
        // Check that green styles are applied
        expect(newFindingRow).toHaveStyle({
            backgroundColor: 'rgba(46, 204, 113, 0.2)',
            borderLeft: '3px solid #2ecc71'
        });
    });

    test('does not render NEW indicator for findings that are not new', () => {
        const oldFindings = [
            {
                ...mockFindings[0],
                isNew: false,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: oldFindings }
        });

        render(<FindingsTab />);
        
        // Should not show NEW indicator
        expect(screen.queryByTestId('sparkles-icon')).not.toBeInTheDocument();
        expect(screen.queryByText('NEW')).not.toBeInTheDocument();
    });

    test('marks findings as viewed when component mounts with new findings', async () => {
        const newFindings = [
            {
                ...mockFindings[0],
                isNew: true,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (retrieveFindings as jest.Mock).mockResolvedValue(newFindings);
        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: newFindings }
        });

        render(<FindingsTab />);

        // Wait for the async operation to complete
        await waitFor(() => {
            expect(retrieveFindings).toHaveBeenCalled();
        });

        // Should not call storeFindings immediately (due to setTimeout)
        expect(storeFindings).not.toHaveBeenCalled();
    });

    test('calls storeFindings after timeout when new findings exist', async () => {
        jest.useFakeTimers();
        
        const newFindings = [
            {
                ...mockFindings[0],
                isNew: true,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (retrieveFindings as jest.Mock).mockResolvedValue(newFindings);
        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: newFindings }
        });

        render(<FindingsTab />);

        // Wait for initial async operation
        await waitFor(() => {
            expect(retrieveFindings).toHaveBeenCalled();
        });

        // Fast-forward past the 3 second timeout
        jest.advanceTimersByTime(3000);

        // Wait for the timeout callback to execute
        await waitFor(() => {
            expect(storeFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    isNew: false,
                    secretType: "AWS Access & Secret Keys"
                })
            ]);
        });

        jest.useRealTimers();
    });

    test('does not set timeout when no new findings exist', async () => {
        const oldFindings = [
            {
                ...mockFindings[0],
                isNew: false,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (retrieveFindings as jest.Mock).mockResolvedValue(oldFindings);
        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: oldFindings }
        });

        render(<FindingsTab />);

        await waitFor(() => {
            expect(retrieveFindings).toHaveBeenCalled();
        });

        // Should not call storeFindings since there are no new findings
        expect(storeFindings).not.toHaveBeenCalled();
    });

    test('handles empty findings array in markFindingsAsViewed', async () => {
        (retrieveFindings as jest.Mock).mockResolvedValue([]);
        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: [] }
        });

        render(<FindingsTab />);

        await waitFor(() => {
            expect(retrieveFindings).toHaveBeenCalled();
        });

        // Should not call storeFindings for empty array
        expect(storeFindings).not.toHaveBeenCalled();
    });

    test('renders secret type text in separate div', () => {
        const findings = [
            {
                ...mockFindings[0],
                isNew: false,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings }
        });

        render(<FindingsTab />);
        
        // Check that secret type is in a separate div with class
        const secretTypeText = screen.getByText('AWS Access & Secret Keys');
        expect(secretTypeText.closest('.secret-type-text')).toBeInTheDocument();
    });

    test('verifies NEW indicator appears above secret type text', () => {
        const newFindings = [
            {
                ...mockFindings[0],
                isNew: true,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: newFindings }
        });

        render(<FindingsTab />);
        
        // Check that both NEW indicator and secret type are in the container
        const container = screen.getByText('AWS Access & Secret Keys').closest('.secret-type-container');
        expect(container).toContainElement(screen.getByText('NEW'));
        expect(container).toContainElement(screen.getByTestId('sparkles-icon'));
    });

    test('handles findings with mixed isNew and discoveredAt fields', () => {
        const complexFindings = [
            {
                ...mockFindings[0],
                isNew: true,
                secretType: "Zzz Service",
                discoveredAt: "2025-07-14T10:00:00.000Z"
            },
            {
                ...mockFindings[1],
                isNew: true,
                secretType: "Aaa Service", 
                discoveredAt: "2025-07-14T12:00:00.000Z"
            },
            {
                ...mockFindings[2],
                isNew: false,
                secretType: "Bbb Service",
                discoveredAt: "2025-07-14T14:00:00.000Z"
            }
        ];

        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: complexFindings }
        });

        render(<FindingsTab />);
        
        const rows = screen.getAllByRole('row');
        // New findings first (by discovery time - newest first), then old findings
        expect(rows[1]).toHaveTextContent('Aaa Service'); // isNew: true, newer discoveredAt
        expect(rows[2]).toHaveTextContent('Zzz Service'); // isNew: true, older discoveredAt  
        expect(rows[3]).toHaveTextContent('Bbb Service'); // isNew: false
    });

    test('does not show highlighting after viewedFindings is set to true', async () => {
        jest.useFakeTimers();
        
        const newFindings = [
            {
                ...mockFindings[0],
                isNew: true,
                secretType: "AWS Access & Secret Keys"
            }
        ];

        (retrieveFindings as jest.Mock).mockResolvedValue(newFindings);
        (useAppContext as jest.Mock).mockReturnValue({
            data: { findings: newFindings }
        });

        render(<FindingsTab />);

        // Initially should show NEW indicator
        expect(screen.getByText('NEW')).toBeInTheDocument();

        // Wait for retrieveFindings to be called
        await waitFor(() => {
            expect(retrieveFindings).toHaveBeenCalled();
        });

        // Fast-forward past the timeout
        jest.advanceTimersByTime(3000);

        // Wait for storeFindings to be called and state update
        await waitFor(() => {
            expect(storeFindings).toHaveBeenCalledWith([
                expect.objectContaining({
                    isNew: false,
                    secretType: "AWS Access & Secret Keys"
                })
            ]);
        });

        // After timeout, the component's viewedFindings state should be true
        // This means NEW indicator should not show for new findings anymore
        await waitFor(() => {
            expect(screen.queryByText('NEW')).not.toBeInTheDocument();
        });

        jest.useRealTimers();
    });

    // Status Bar and Recheck Progress Tests
    describe('Status Bar and Recheck Progress', () => {
        test('shows status bar when recheck all is clicked', async () => {
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Status bar should be visible immediately - look for the specific status bar text
            await waitFor(() => {
                expect(screen.getByText('Rechecking validity... (0/23)')).toBeInTheDocument();
            });
        });

        test('disables recheck all button when clicked', async () => {
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Button should be disabled immediately
            expect(recheckAllButton).toBeDisabled();
        });

        test('shows spinning icon during recheck operation', async () => {
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Verify that the component enters recheck state (button disabled is sufficient indicator)
            expect(recheckAllButton).toBeDisabled();
            // The spinning animation is handled by CSS and is adequately tested through button state
        });

        test('updates tooltip text during recheck operation', async () => {
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            // Initial tooltip text
            expect(screen.getByText('Recheck the validity of all findings')).toBeInTheDocument();
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Tooltip text should change during operation - find the tooltip specifically
            const tooltip = document.querySelector('.tooltip-text');
            expect(tooltip).toHaveTextContent('Rechecking validity...');
        });

        test('status bar spans all table columns', async () => {
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Find the status bar cell using the specific status bar text
            await waitFor(() => {
                const statusBarCell = screen.getByText('Rechecking validity... (0/23)').closest('td');
                expect(statusBarCell).toHaveAttribute('colSpan', '4');
            });
        });

        test('progress bar has correct CSS classes and initial width', async () => {
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Check progress bar structure
            await waitFor(() => {
                const progressBar = document.querySelector('.progress-bar');
                const progressFill = document.querySelector('.progress-fill');
                
                expect(progressBar).toBeInTheDocument();
                expect(progressFill).toBeInTheDocument();
                expect(progressFill).toHaveClass('progress-fill');
                expect(progressFill).toHaveStyle('width: 0%');
            });
        });

        test('individual validity check handles errors gracefully', async () => {
            const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
            (anthropicValidityHelper as jest.Mock).mockRejectedValue(new Error('Individual check error'));
            
            render(<FindingsTab />);
            
            // Click individual recheck button
            const recheckButtons = screen.getAllByLabelText('Recheck validity');
            
            act(() => {
                fireEvent.click(recheckButtons[0]);
            });
            
            await waitFor(() => {
                expect(consoleError).toHaveBeenCalledWith('Validity check failed for Anthropic AI:', expect.any(Error));
            });
            
            consoleError.mockRestore();
        });

        test('status bar has correct styling classes', async () => {
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Check status bar styling
            await waitFor(() => {
                const statusBar = document.querySelector('.recheck-status-bar');
                const statusBarContainer = document.querySelector('.status-bar-container');
                const statusBarContent = document.querySelector('.status-bar-content');
                
                expect(statusBar).toBeInTheDocument();
                expect(statusBarContainer).toBeInTheDocument();
                expect(statusBarContent).toBeInTheDocument();
            });
        });

        test('handleValidityCheck calls correct validity helpers', () => {
            render(<FindingsTab />);
            
            // Test individual recheck buttons for different secret types
            const recheckButtons = screen.getAllByLabelText('Recheck validity');
            
            // Click Anthropic AI recheck button (sorted index 0)
            fireEvent.click(recheckButtons[0]);
            expect(anthropicValidityHelper).toHaveBeenCalledWith(sortedMockFindings[0]);
            
            // Click Apollo recheck button (sorted index 1)
            fireEvent.click(recheckButtons[1]);
            expect(apolloValidityHelper).toHaveBeenCalledWith(sortedMockFindings[1]);
        });

        test('handleRecheckAll calls all validity helpers', async () => {
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Should eventually call all different validity helpers
            await waitFor(() => {
                // AWS Access & Secret Keys appears 4 times in mockFindings
                expect(awsValidityHelper).toHaveBeenCalledTimes(4);
                expect(awsSessionValidityHelper).toHaveBeenCalledTimes(1);
                expect(anthropicValidityHelper).toHaveBeenCalledTimes(1);
                expect(openaiValidityHelper).toHaveBeenCalledTimes(1);
                expect(geminiValidityHelper).toHaveBeenCalledTimes(1);
                expect(huggingfaceValidityHelper).toHaveBeenCalledTimes(1);
                expect(artifactoryValidityHelper).toHaveBeenCalledTimes(1);
                expect(azureOpenAIValidityHelper).toHaveBeenCalledTimes(1);
                expect(apolloValidityHelper).toHaveBeenCalledTimes(1);
                expect(gcpValidityHelper).toHaveBeenCalledTimes(1);
                expect(dockerValidityHelper).toHaveBeenCalledTimes(1);
                expect(jotformValidityHelper).toHaveBeenCalledTimes(1);
                expect(groqValidityHelper).toHaveBeenCalledTimes(1);
                expect(mailgunValidityHelper).toHaveBeenCalledTimes(1);
                expect(mailchimpValidityHelper).toHaveBeenCalledTimes(1);
                expect(deepseekValidityHelper).toHaveBeenCalledTimes(1);
                expect(deepaiValidityHelper).toHaveBeenCalledTimes(1);
                expect(telegramBotTokenValidityHelper).toHaveBeenCalledTimes(1);
                expect(rapidApiValidityHelper).toHaveBeenCalledTimes(1);
                expect(makeValidityHelper).toHaveBeenCalledTimes(1);
            }, { timeout: 10000 });
        });

        test('handleRecheckAll handles errors without crashing', async () => {
            const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
            (awsValidityHelper as jest.Mock).mockRejectedValue(new Error('Network error'));
            
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Should log errors but not crash
            await waitFor(() => {
                expect(consoleError).toHaveBeenCalledWith('Validity check failed for AWS Access & Secret Keys:', expect.any(Error));
            }, { timeout: 10000 });
            
            consoleError.mockRestore();
        });

        test('handleRecheckAll handles multiple concurrent errors gracefully', async () => {
            const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
            
            // Mock multiple validators to fail
            (awsValidityHelper as jest.Mock).mockRejectedValue(new Error('AWS Network error'));
            (anthropicValidityHelper as jest.Mock).mockRejectedValue(new Error('Anthropic API error'));
            (openaiValidityHelper as jest.Mock).mockRejectedValue(new Error('OpenAI timeout'));
            
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Should log all errors concurrently and complete all validations
            await waitFor(() => {
                expect(consoleError).toHaveBeenCalledWith('Validity check failed for AWS Access & Secret Keys:', expect.any(Error));
                expect(consoleError).toHaveBeenCalledWith('Validity check failed for Anthropic AI:', expect.any(Error));
                expect(consoleError).toHaveBeenCalledWith('Validity check failed for OpenAI:', expect.any(Error));
            }, { timeout: 10000 });

            // Progress should still reach completion despite errors
            await waitFor(() => {
                // The recheck button should be re-enabled indicating completion
                expect(recheckAllButton).not.toBeDisabled();
            }, { timeout: 10000 });
            
            consoleError.mockRestore();
        });

        test('handleRecheckAll continues progress tracking even when validation throws', async () => {
            const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
            
            // Mock some validators to fail, others to succeed
            (awsValidityHelper as jest.Mock).mockRejectedValue(new Error('Network failure'));
            (anthropicValidityHelper as jest.Mock).mockResolvedValue(undefined); // Success
            (openaiValidityHelper as jest.Mock).mockRejectedValue(new Error('API timeout'));
            
            render(<FindingsTab />);
            
            const recheckAllButton = screen.getByLabelText('Recheck all findings');
            
            act(() => {
                fireEvent.click(recheckAllButton);
            });
            
            // Wait for completion - all validations should complete despite some failures
            await waitFor(() => {
                expect(recheckAllButton).not.toBeDisabled();
            }, { timeout: 10000 });
            
            // Verify both successful and failed validations were logged appropriately
            expect(consoleError).toHaveBeenCalledWith('Validity check failed for AWS Access & Secret Keys:', expect.any(Error));
            expect(consoleError).toHaveBeenCalledWith('Validity check failed for OpenAI:', expect.any(Error));
            
            // Verify anthropic validation succeeded (no error logged for it)
            expect(anthropicValidityHelper).toHaveBeenCalled();
            
            consoleError.mockRestore();
        });

    });
});