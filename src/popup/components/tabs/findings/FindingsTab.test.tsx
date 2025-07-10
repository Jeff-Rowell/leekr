import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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

jest.mock('../../../../utils/helpers/common', () => ({
    retrieveFindings: jest.fn(),
    storeFindings: jest.fn(),
}));

jest.mock('./style.css', () => ({}));

jest.mock('lucide-react', () => ({
    RotateCw: () => <div data-testid="rotate-cw-icon" />,
    Settings: () => <div data-testid="settings-icon" />,
    ShieldCheck: () => <svg data-testid="shield-check-icon" />,
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
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindings,
            },
        });

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
        expect(rows[1]).toHaveTextContent('AWS Access & Secret Keys');
        expect(rows[1]).toHaveTextContent('valid');
        expect(rows[1]).toHaveTextContent('1');

        expect(rows[2]).toHaveTextContent('AWS Access & Secret Keys');
        expect(rows[2]).toHaveTextContent('invalid');
        expect(rows[2]).toHaveTextContent('1');

        expect(rows[3]).toHaveTextContent('AWS Access & Secret Keys');
        expect(rows[3]).toHaveTextContent('unknown');
        expect(rows[3]).toHaveTextContent('1');

        expect(rows[4]).toHaveTextContent('AWS Access & Secret Keys');
        expect(rows[4]).toHaveTextContent('failed to check');
        expect(rows[4]).toHaveTextContent('1');

        expect(rows[5]).toHaveTextContent('AWS Session Keys');
        expect(rows[5]).toHaveTextContent('valid');
        expect(rows[5]).toHaveTextContent('1');

        expect(rows[6]).toHaveTextContent('Anthropic AI');
        expect(rows[6]).toHaveTextContent('valid');
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
        expect(shieldIcons.length).toBe(18);
    });

    test('opens settings menu when settings button is clicked', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        expect(settingsButtons.length).toBe(18);
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
        expect(recheckButtons).toHaveLength(18);

        fireEvent.click(recheckButtons[0]);
        expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[0]);
    });

    test('calls awsSessionValidityHelper when recheck button is clicked for AWS Session Keys', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);

        fireEvent.click(recheckButtons[4]);
        expect(awsSessionValidityHelper).toHaveBeenCalledWith(mockFindings[4]);
    });

    test('calls anthropicValidityHelper when recheck button is clicked for Anthropic AI', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);

        fireEvent.click(recheckButtons[5]);
        expect(anthropicValidityHelper).toHaveBeenCalledWith(mockFindings[5]);
    });

    test('calls openaiValidityHelper when recheck button is clicked for OpenAI', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);

        fireEvent.click(recheckButtons[6]);
        expect(openaiValidityHelper).toHaveBeenCalledWith(mockFindings[6]);
    });

    test('calls geminiValidityHelper when recheck button is clicked for Gemini', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);

        fireEvent.click(recheckButtons[7]);
        expect(geminiValidityHelper).toHaveBeenCalledWith(mockFindings[7]);
    });

    test('calls huggingfaceValidityHelper when recheck button is clicked for Hugging Face', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);

        fireEvent.click(recheckButtons[8]);
        expect(huggingfaceValidityHelper).toHaveBeenCalledWith(mockFindings[8]);
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
            url: 'chrome-extension://extension-id/options.html?tab=findings&fingerprint=fp1'
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
        expect(recheckButtons).toHaveLength(18);
        
        // Click the Artifactory recheck button (10th button, index 9) 
        fireEvent.click(recheckButtons[9]);
        
        // Verify artifactory validity helper was called
        expect(artifactoryValidityHelper).toHaveBeenCalledWith(mockFindings[9]);
    });

    test('calls azureOpenAIValidityHelper for Azure OpenAI findings', async () => {
        render(<FindingsTab />);
        
        // Find the Azure OpenAI recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);
        
        // Click the last recheck button (Azure OpenAI finding)
        fireEvent.click(recheckButtons[10]);
        
        // Verify azure openai validity helper was called
        expect(azureOpenAIValidityHelper).toHaveBeenCalledWith(mockFindings[10]);
    });

    test('calls apolloValidityHelper for Apollo findings', async () => {
        render(<FindingsTab />);
        
        // Find the Apollo recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);
        
        // Click the Apollo recheck button (12th button, index 11)
        fireEvent.click(recheckButtons[11]);
        
        // Verify apollo validity helper was called
        expect(apolloValidityHelper).toHaveBeenCalledWith(mockFindings[11]);
    });

    test('calls gcpValidityHelper for Google Cloud Platform findings', async () => {
        render(<FindingsTab />);
        
        // Find the GCP recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);
        
        // Click the last recheck button (GCP finding)
        fireEvent.click(recheckButtons[12]);
        
        // Verify gcp validity helper was called
        expect(gcpValidityHelper).toHaveBeenCalledWith(mockFindings[12]);
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
        expect(recheckButtons).toHaveLength(18);
        
        // Click the Docker recheck button (14th button, index 13)
        fireEvent.click(recheckButtons[13]);
        
        // Verify docker validity helper was called
        expect(dockerValidityHelper).toHaveBeenCalledWith(mockFindings[13]);
    });

    test('calls jotformValidityHelper when recheck button is clicked for JotForm', async () => {
        render(<FindingsTab />);
        
        // Find the JotForm recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);
        
        // Click the JotForm recheck button (15th button, index 14)
        fireEvent.click(recheckButtons[14]);
        
        // Verify jotform validity helper was called
        expect(jotformValidityHelper).toHaveBeenCalledWith(mockFindings[14]);
    });

    test('calls groqValidityHelper when recheck button is clicked for Groq', async () => {
        render(<FindingsTab />);
        
        // Find the Groq recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);
        
        // Click the Groq recheck button (16th button, index 15)
        fireEvent.click(recheckButtons[15]);
        
        // Verify groq validity helper was called
        expect(groqValidityHelper).toHaveBeenCalledWith(mockFindings[15]);
    });

    test('calls mailgunValidityHelper when recheck button is clicked for Mailgun', async () => {
        render(<FindingsTab />);
        
        // Find the Mailgun recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);
        
        // Click the Mailgun recheck button (17th button, index 16)
        fireEvent.click(recheckButtons[16]);
        
        // Verify mailgun validity helper was called
        expect(mailgunValidityHelper).toHaveBeenCalledWith(mockFindings[16]);
    });

    test('calls mailchimpValidityHelper when recheck button is clicked for Mailchimp', async () => {
        render(<FindingsTab />);
        
        // Find the Mailchimp recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(18);
        
        // Click the Mailchimp recheck button (18th button, index 17)
        fireEvent.click(recheckButtons[17]);
        
        // Verify mailchimp validity helper was called
        expect(mailchimpValidityHelper).toHaveBeenCalledWith(mockFindings[17]);
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
        fireEvent.click(recheckAllButton);
        
        // Wait for all validity helpers to be called
        await waitFor(() => {
            // Check that awsValidityHelper was called for all AWS Access & Secret Keys findings
            expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[0]);
            expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[1]);
            expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[2]);
            expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[3]);
            
            // Check individual service validity helpers
            expect(awsSessionValidityHelper).toHaveBeenCalledWith(mockFindings[4]);
            expect(anthropicValidityHelper).toHaveBeenCalledWith(mockFindings[5]);
            expect(openaiValidityHelper).toHaveBeenCalledWith(mockFindings[6]);
            expect(geminiValidityHelper).toHaveBeenCalledWith(mockFindings[7]);
            expect(huggingfaceValidityHelper).toHaveBeenCalledWith(mockFindings[8]);
            expect(artifactoryValidityHelper).toHaveBeenCalledWith(mockFindings[9]);
            expect(azureOpenAIValidityHelper).toHaveBeenCalledWith(mockFindings[10]);
            expect(apolloValidityHelper).toHaveBeenCalledWith(mockFindings[11]);
            expect(gcpValidityHelper).toHaveBeenCalledWith(mockFindings[12]);
            expect(dockerValidityHelper).toHaveBeenCalledWith(mockFindings[13]);
            expect(jotformValidityHelper).toHaveBeenCalledWith(mockFindings[14]);
            expect(groqValidityHelper).toHaveBeenCalledWith(mockFindings[15]);
            expect(mailgunValidityHelper).toHaveBeenCalledWith(mockFindings[16]);
            expect(mailchimpValidityHelper).toHaveBeenCalledWith(mockFindings[17]);
        });
    });

    test('renders tooltip icon and text for recheck all button', () => {
        render(<FindingsTab />);
        
        // Check that the tooltip text is rendered
        const tooltipText = screen.getByText('Recheck the validity of all findings');
        expect(tooltipText).toBeInTheDocument();
    });
});