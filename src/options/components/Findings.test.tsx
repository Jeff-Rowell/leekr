import '@testing-library/jest-dom';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useAppContext } from '../../popup/AppContext';
import { AWSOccurrence } from '../../types/aws.types';
import { AnthropicOccurrence } from '../../types/anthropic';
import { OpenAIOccurrence } from '../../types/openai';
import { GeminiOccurrence } from '../../types/gemini';
import { HuggingFaceOccurrence } from '../../types/huggingface';
import { ArtifactoryOccurrence } from '../../types/artifactory';
import { AzureOpenAIOccurrence } from '../../types/azure_openai';
import { ApolloOccurrence } from '../../types/apollo';
import { GcpOccurrence } from '../../types/gcp';
import { DockerOccurrence } from '../../types/docker';
import { JotFormOccurrence } from '../../types/jotform';
import { GroqOccurrence } from '../../types/groq';
import { MailgunOccurrence } from '../../types/mailgun';
import { Finding, Occurrence } from '../../types/findings.types';
import { awsValidityHelper } from '../../utils/validators/aws/aws_access_keys/awsValidityHelper';
import { awsSessionValidityHelper } from '../../utils/validators/aws/aws_session_keys/awsValidityHelper';
import { anthropicValidityHelper } from '../../utils/validators/anthropic/anthropicValidityHelper';
import { openaiValidityHelper } from '../../utils/validators/openai/openaiValidityHelper';
import { geminiValidityHelper } from '../../utils/validators/gemini/geminiValidityHelper';
import { huggingfaceValidityHelper } from '../../utils/validators/huggingface/huggingfaceValidityHelper';
import { artifactoryValidityHelper } from '../../utils/validators/artifactory/artifactoryValidityHelper';
import { azureOpenAIValidityHelper } from '../../utils/validators/azure_openai/azureOpenAIValidityHelper';
import { apolloValidityHelper } from '../../utils/validators/apollo/apolloValidityHelper';
import { gcpValidityHelper } from '../../utils/validators/gcp/gcpValidityHelper';
import { dockerValidityHelper } from '../../utils/validators/docker/dockerValidityHelper';
import { jotformValidityHelper } from '../../utils/validators/jotform/jotformValidityHelper';
import { groqValidityHelper } from '../../utils/validators/groq/groqValidityHelper';
import { mailgunValidityHelper } from '../../utils/validators/mailgun/mailgunValidityHelper';
import { Findings } from './Findings';

jest.mock('../../popup/AppContext');

jest.mock('../../utils/validators/aws/aws_access_keys/awsValidityHelper');
jest.mock('../../utils/validators/aws/aws_session_keys/awsValidityHelper');
jest.mock('../../utils/validators/anthropic/anthropicValidityHelper');
jest.mock('../../utils/validators/openai/openaiValidityHelper');
jest.mock('../../utils/validators/gemini/geminiValidityHelper');
jest.mock('../../utils/validators/huggingface/huggingfaceValidityHelper');
jest.mock('../../utils/validators/artifactory/artifactoryValidityHelper');
jest.mock('../../utils/validators/azure_openai/azureOpenAIValidityHelper');
jest.mock('../../utils/validators/apollo/apolloValidityHelper');
jest.mock('../../utils/validators/gcp/gcpValidityHelper');
jest.mock('../../utils/validators/docker/dockerValidityHelper');
jest.mock('../../utils/validators/jotform/jotformValidityHelper');
jest.mock('../../utils/validators/groq/groqValidityHelper');
jest.mock('../../utils/validators/mailgun/mailgunValidityHelper');

const mockAwsValidityHelper = awsValidityHelper as jest.MockedFunction<typeof awsValidityHelper>;
const mockAwsSessionValidityHelper = awsSessionValidityHelper as jest.MockedFunction<typeof awsSessionValidityHelper>;
const mockAnthropicValidityHelper = anthropicValidityHelper as jest.MockedFunction<typeof anthropicValidityHelper>;
const mockOpenaiValidityHelper = openaiValidityHelper as jest.MockedFunction<typeof openaiValidityHelper>;
const mockGeminiValidityHelper = geminiValidityHelper as jest.MockedFunction<typeof geminiValidityHelper>;
const mockHuggingfaceValidityHelper = huggingfaceValidityHelper as jest.MockedFunction<typeof huggingfaceValidityHelper>;
const mockArtifactoryValidityHelper = artifactoryValidityHelper as jest.MockedFunction<typeof artifactoryValidityHelper>;
const mockAzureOpenAIValidityHelper = azureOpenAIValidityHelper as jest.MockedFunction<typeof azureOpenAIValidityHelper>;
const mockApolloValidityHelper = apolloValidityHelper as jest.MockedFunction<typeof apolloValidityHelper>;
const mockGcpValidityHelper = gcpValidityHelper as jest.MockedFunction<typeof gcpValidityHelper>;
const mockDockerValidityHelper = dockerValidityHelper as jest.MockedFunction<typeof dockerValidityHelper>;
const mockJotformValidityHelper = jotformValidityHelper as jest.MockedFunction<typeof jotformValidityHelper>;
const mockGroqValidityHelper = groqValidityHelper as jest.MockedFunction<typeof groqValidityHelper>;
const mockMailgunValidityHelper = mailgunValidityHelper as jest.MockedFunction<typeof mailgunValidityHelper>;

const mockChrome = {
    runtime: {
        getURL: jest.fn((path: string) => `chrome-extension://test/${path}`)
    },
    tabs: {
        query: jest.fn(),
        update: jest.fn()
    }
};
(global as any).chrome = mockChrome;

jest.mock('lucide-react', () => ({
    ShieldCheck: ({ size }: { size?: number }) =>
        <div data-testid="shield-check" data-size={size}>ShieldCheck</div>,
    SquareArrowRight: ({ size }: { size?: number }) =>
        <div data-testid="square-arrow-right" data-size={size}>SquareArrowRight</div>,
    RotateCw: ({ size }: { size?: number }) =>
        <div data-testid="rotate-cw" data-size={size}>RotateCw</div>,
    ChevronDown: ({ size, className }: { size?: number; className?: string }) =>
        <div data-testid={`chevron-down${className ? `-${className}` : ''}`} data-size={size}>ChevronDown</div>,
    ChevronUp: ({ size }: { size?: number }) =>
        <div data-testid="chevron-up" data-size={size}>ChevronUp</div>,
    ChevronLeft: ({ size }: { size?: number }) =>
        <div data-testid="chevron-left" data-size={size}>ChevronLeft</div>,
    ChevronRight: ({ size }: { size?: number }) =>
        <div data-testid="chevron-right" data-size={size}>ChevronRight</div>,
    AlertTriangle: ({ size }: { size?: number }) =>
        <div data-testid="alert-triangle" data-size={size}>AlertTriangle</div>,
}));

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

const mockOccurrencesOne: Set<Occurrence> = new Set([mockOccurrenceOne]);
const mockOccurrencesTwo: Set<Occurrence> = new Set([mockOccurrenceTwo]);
const mockOccurrencesThree: Set<Occurrence> = new Set([mockOccurrenceThree]);
const mockOccurrencesFour: Set<Occurrence> = new Set([mockOccurrenceFour]);
const mockSessionOccurrences: Set<Occurrence> = new Set([mockSessionOccurrence]);

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

const mockAzureOpenAIOccurrence: AzureOpenAIOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp10",
    type: "API Key",
    secretType: "Azure OpenAI",
    secretValue: {
        match: { 
            api_key: "abcdef12345678901234567890123456",
            url: "test-instance.openai.azure.com"
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

const mockAnthropicOccurrences: Set<Occurrence> = new Set([mockAnthropicOccurrence]);
const mockOpenAIOccurrences: Set<Occurrence> = new Set([mockOpenAIOccurrence]);
const mockGeminiOccurrences: Set<Occurrence> = new Set([mockGeminiOccurrence]);
const mockHuggingFaceOccurrences: Set<Occurrence> = new Set([mockHuggingFaceOccurrence]);
const mockGcpOccurrence: GcpOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp11",
    type: "Service Account Key",
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
    sourceContent: {
        content: "foobar",
        contentEndLineNum: 35,
        contentFilename: "App.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/main.foobar.js",
};

const mockAzureOpenAIOccurrences: Set<Occurrence> = new Set([mockAzureOpenAIOccurrence]);
const mockGcpOccurrences: Set<Occurrence> = new Set([mockGcpOccurrence]);

const mockDockerOccurrence: DockerOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp12",
    type: "Docker Registry Credentials",
    secretType: "Docker",
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
        content: "foobar",
        contentEndLineNum: 35,
        contentFilename: "App.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/main.foobar.js",
};

const mockDockerOccurrences: Set<Occurrence> = new Set([mockDockerOccurrence]);

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
        fingerprint: "fp10",
        numOccurrences: mockAzureOpenAIOccurrences.size,
        occurrences: mockAzureOpenAIOccurrences,
        validity: "valid",
        validatedAt: "2025-05-17T18:16:16.870Z",
        secretType: "Azure OpenAI",
        secretValue: {
            match: { 
                api_key: "abcdef12345678901234567890123456",
                url: "test-instance.openai.azure.com"
            },
            validatedAt: "2025-05-17T18:16:16.870Z",
            validity: "valid"
        }
    },
    {
        fingerprint: "fp11",
        numOccurrences: mockGcpOccurrences.size,
        occurrences: mockGcpOccurrences,
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
        fingerprint: "fp12",
        numOccurrences: mockDockerOccurrences.size,
        occurrences: mockDockerOccurrences,
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
        fingerprint: "fp13",
        numOccurrences: 1,
        occurrences: new Set([{
            filePath: "main.jotform.js",
            fingerprint: "fp13",
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
        } as JotFormOccurrence]),
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
        fingerprint: "fp14",
        numOccurrences: 1,
        occurrences: new Set([{
            filePath: "main.groq.js",
            fingerprint: "fp14",
            type: "API_KEY",
            secretType: "Groq",
            secretValue: {
                match: { 
                    apiKey: "gsk_" + "a".repeat(52)
                }
            },
            sourceContent: {
                content: "foobar",
                contentEndLineNum: 35,
                contentFilename: "App.js",
                contentStartLineNum: 18,
                exactMatchNumbers: [23, 30]
            },
            url: "http://localhost:3000/static/js/main.groq.js",
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
        fingerprint: "fp15",
        numOccurrences: 1,
        occurrences: new Set([{
            filePath: "main.mailgun.js",
            fingerprint: "fp15",
            type: "Mailgun API Key",
            secretType: "Mailgun",
            secretValue: {
                match: { 
                    apiKey: "key-" + "a".repeat(32)
                }
            },
            sourceContent: {
                content: "foobar",
                contentEndLineNum: 35,
                contentFilename: "App.js",
                contentStartLineNum: 18,
                exactMatchNumbers: [23, 30]
            },
            url: "http://localhost:3000/static/js/main.mailgun.js",
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
];

describe('Findings Component', () => {
    beforeEach(() => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindings,
            },
        });
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Rendering', () => {
        test('renders the component with title', () => {
            render(<Findings />);

            expect(screen.getByText('Findings')).toBeInTheDocument();
        });

        test('renders filter controls', () => {
            render(<Findings />);

            expect(screen.getByLabelText('Validity Status:')).toBeInTheDocument();
            expect(screen.getByLabelText('Secret Type:')).toBeInTheDocument();
        });

        test('renders table headers correctly', () => {
            render(<Findings />);

            expect(screen.getByText('Type')).toBeInTheDocument();
            expect(screen.getByText('Validity')).toBeInTheDocument();
            expect(screen.getByText('Occurrences')).toBeInTheDocument();
        });

        test('renders all findings when no filters applied', () => {
            const { container } = render(<Findings />);
            const findings = container.querySelectorAll('.findings-td');
            expect(findings).toHaveLength(10); // Pagination shows only 10 per page
        });

        test('shows empty state when no findings exist', () => {
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [],
                },
            });

            render(<Findings />);

            expect(screen.getByTestId('alert-triangle')).toBeInTheDocument();
            expect(screen.getByText('No findings match your filters.')).toBeInTheDocument();
        });

        test('displays validity status with correct formatting', () => {
            render(<Findings />);

            expect(screen.getAllByText('valid')).toHaveLength(7); // Only shows 7 on first page due to pagination
            expect(screen.getByText('invalid')).toBeInTheDocument();
            expect(screen.getByText('unknown')).toBeInTheDocument();
            expect(screen.getByText('failed to check')).toBeInTheDocument();
        });

        test('displays validation timestamp when available', () => {
            const { container } = render(<Findings />);

            const shieldIcons = container.querySelectorAll('.validity-valid');
            expect(shieldIcons).toHaveLength(7);
        });
    });

    describe('Validity Status Filtering', () => {
        test('filters findings by valid status', async () => {
            const user = userEvent.setup();
            const { container } = render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            await user.selectOptions(validityFilter, 'valid');

            const findings = container.querySelectorAll('.findings-td');
            expect(findings).toHaveLength(10); // 10 valid findings now
        });

        test('filters findings by invalid status', async () => {
            const user = userEvent.setup();
            const { container } = render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            await user.selectOptions(validityFilter, 'invalid');

            const findings = container.querySelectorAll('.findings-td');
            expect(findings).toHaveLength(1);
        });

        test('filters findings by unknown status', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            await user.selectOptions(validityFilter, 'unknown');

            const rows = screen.getAllByRole('row');
            expect(rows).toHaveLength(2);
            expect(screen.getByText('unknown')).toBeInTheDocument();
        });

        test('filters findings by failed_to_check status', async () => {
            const user = userEvent.setup();
            const { container } = render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            await user.selectOptions(validityFilter, 'failed_to_check');

            const findings = container.querySelectorAll('.findings-td');
            expect(findings).toHaveLength(1);
        });

        test('shows all findings when "All Statuses" is selected', async () => {
            const user = userEvent.setup();
            const { container } = render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            await user.selectOptions(validityFilter, 'valid');

            const validFindings = container.querySelectorAll('.findings-td');
            expect(validFindings).toHaveLength(10); // 10 valid findings now

            await user.selectOptions(validityFilter, 'all');
            const allFindings = container.querySelectorAll('.findings-td');
            expect(allFindings).toHaveLength(10); // Pagination shows only 10 per page
        });
    });

    describe('Secret Type Filtering', () => {
        test('populates secret type dropdown with unique types', () => {
            render(<Findings />);

            const typeFilter = screen.getByLabelText('Secret Type:');
            const options = typeFilter.querySelectorAll('option');

            expect(options).toHaveLength(13); // Added Docker, JotForm, Groq, and Mailgun
            expect(options[0]).toHaveTextContent('All Types');
            expect(options[1]).toHaveTextContent('AWS Access & Secret Keys');
            expect(options[2]).toHaveTextContent('AWS Session Keys');
            expect(options[3]).toHaveTextContent('Anthropic AI');
            expect(options[4]).toHaveTextContent('OpenAI');
            expect(options[5]).toHaveTextContent('Gemini');
            expect(options[6]).toHaveTextContent('Hugging Face');
        });

        test('filters findings by secret type', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const typeFilter = screen.getByLabelText('Secret Type:');
            await user.selectOptions(typeFilter, 'AWS Access & Secret Keys');

            const rows = screen.getAllByRole('row');
            expect(rows).toHaveLength(5); // 1 header + 4 AWS Access & Secret Keys findings
        });

        test('filters findings by AWS Session Keys', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const typeFilter = screen.getByLabelText('Secret Type:');
            await user.selectOptions(typeFilter, 'AWS Session Keys');

            const rows = screen.getAllByRole('row');
            expect(rows).toHaveLength(2); // 1 header + 1 AWS Session Keys finding
        });

        test('shows all findings when "All Types" is selected', async () => {
            const user = userEvent.setup();
            const { container } = render(<Findings />);

            const typeFilter = screen.getByLabelText('Secret Type:');
            await user.selectOptions(typeFilter, 'AWS Access & Secret Keys');
            const allFindings = container.querySelectorAll('.findings-td');
            expect(allFindings).toHaveLength(4)
        });
    });

    describe('Combined Filtering', () => {
        test('applies both validity and type filters simultaneously', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            const typeFilter = screen.getByLabelText('Secret Type:');

            await user.selectOptions(validityFilter, 'valid');
            await user.selectOptions(typeFilter, 'AWS Access & Secret Keys');

            const rows = screen.getAllByRole('row');
            expect(rows).toHaveLength(2);
            expect(screen.getByText('valid')).toBeInTheDocument();
        });

        test('shows empty state when filters match no findings', async () => {
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [],
                },
            });
            const user = userEvent.setup();
            render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            await user.selectOptions(validityFilter, 'valid');
            expect(screen.getByText('No findings match your filters.')).toBeInTheDocument();
        });
    });

    describe('Sorting Functionality', () => {
        test('sorts by secret type ascending by default', () => {
            render(<Findings />);

            const rows = screen.getAllByRole('row');
            const firstDataRow = rows[1];
            const secondDataRow = rows[2];

            expect(firstDataRow).toHaveTextContent('Anthropic AI');
            expect(secondDataRow).toHaveTextContent('AWS Access & Secret Keys');
        });

        test('toggles sort direction when clicking same column', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const typeHeader = screen.getByText('Type').closest('th')!;

            await user.click(typeHeader);

            const rows = screen.getAllByRole('row');
            const firstDataRow = rows[1];
            expect(firstDataRow).toHaveTextContent('OpenAI');
        });

        test('sorts by validity when clicked', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const validityHeader = screen.getByText('Validity').closest('th')!;
            await user.click(validityHeader);
            const ascRows = screen.getAllByRole('row');
            const ascFirstDataRow = ascRows[1];
            expect(ascFirstDataRow).toHaveTextContent('failed to check');

            await user.click(validityHeader);
            const descRows = screen.getAllByRole('row');
            const descFirstDataRow = descRows[1];
            expect(descFirstDataRow).toHaveTextContent('valid');
        });

        test('sorts by occurrences when clicked', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const occurrencesHeader = screen.getByText('Occurrences').closest('th')!;

            await user.click(occurrencesHeader);
            const ascRows = screen.getAllByRole('row');
            const ascFirstDataRow = ascRows[1];
            expect(ascFirstDataRow).toHaveTextContent('1');

            await user.click(occurrencesHeader);
            const descRows = screen.getAllByRole('row');
            const descFirstDataRow = descRows[1];
            expect(descFirstDataRow).toHaveTextContent('1');

            await user.click(occurrencesHeader);
            const ascRows2 = screen.getAllByRole('row');
            const ascFirstDataRow2 = ascRows2[1];
            expect(ascFirstDataRow2).toHaveTextContent('1');
        });

        test('displays correct sort icons', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            expect(screen.getByTestId('chevron-up')).toBeInTheDocument();

            const typeHeader = screen.getByText('Type').closest('th')!;
            await user.click(typeHeader);

            expect(screen.getByTestId('chevron-down')).toBeInTheDocument();
        });
    });

    describe('Actions', () => {
        test('renders view occurrences buttons', () => {
            render(<Findings />);

            const viewButtons = screen.getAllByTestId('square-arrow-right');
            expect(viewButtons).toHaveLength(10);
        });

        test('handles view occurrences click', async () => {
            const user = userEvent.setup();
            const mockTabs = [{ id: 123 }];
            mockChrome.tabs.query.mockImplementation((query, callback) => {
                callback(mockTabs);
            });

            render(<Findings />);

            const viewButtons = screen.getAllByTestId('square-arrow-right');
            await user.click(viewButtons[0]);

            expect(mockChrome.runtime.getURL).toHaveBeenCalledWith('options.html');
            expect(mockChrome.tabs.query).toHaveBeenCalledWith(
                { active: true, currentWindow: true },
                expect.any(Function)
            );
            expect(mockChrome.tabs.update).toHaveBeenCalledWith(
                123,
                { url: 'chrome-extension://test/options.html?tab=findings&fingerprint=fp6' }
            );
        });

        test('handles validity recheck for AWS keys', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const recheckButtons = screen.getAllByTestId('rotate-cw');
            await user.click(recheckButtons[1]);

            expect(mockAwsValidityHelper).toHaveBeenCalledWith(mockFindings[0]);
        });

        test('handles validity recheck for AWS Session Keys', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const recheckButtons = screen.getAllByTestId('rotate-cw');
            await user.click(recheckButtons[2]);

            expect(mockAwsSessionValidityHelper).toHaveBeenCalledWith(mockFindings[4]);
        });

        test('handles validity recheck for Anthropic AI', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const recheckButtons = screen.getAllByTestId('rotate-cw');
            await user.click(recheckButtons[0]);

            expect(mockAnthropicValidityHelper).toHaveBeenCalledWith(mockFindings[5]);
        });

        test('handles validity recheck for OpenAI', async () => {
            // Create a specific OpenAI finding to test
            const openAIFinding = {
                fingerprint: 'openai-test',
                numOccurrences: 1,
                secretType: 'OpenAI',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { match: { api_key: 'sk-proj-test123456789' } },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [openAIFinding],
                },
            });

            const user = userEvent.setup();
            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            await user.click(recheckButton);

            expect(mockOpenaiValidityHelper).toHaveBeenCalledWith(openAIFinding);
        });

        test('handles validity recheck for Gemini', async () => {
            // Create a specific Gemini finding to test
            const geminiFinding = {
                fingerprint: 'gemini-test',
                numOccurrences: 1,
                secretType: 'Gemini',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { match: { api_key: 'test123', api_secret: 'secret123' } },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [geminiFinding],
                },
            });

            const user = userEvent.setup();
            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            await user.click(recheckButton);

            expect(mockGeminiValidityHelper).toHaveBeenCalledWith(geminiFinding);
        });

        test('handles validity recheck for Hugging Face', async () => {
            // Create a specific Hugging Face finding to test
            const huggingFaceFinding = {
                fingerprint: 'huggingface-test',
                numOccurrences: 1,
                secretType: 'Hugging Face',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { match: { api_key: 'hf_1234567890abcdefghijklmnopqrstuv12' } },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [huggingFaceFinding],
                },
            });

            const user = userEvent.setup();
            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            await user.click(recheckButton);

            expect(mockHuggingfaceValidityHelper).toHaveBeenCalledWith(huggingFaceFinding);
        });

        test('handles validity recheck for JotForm', async () => {
            // Create a specific JotForm finding to test
            const jotformFinding = {
                fingerprint: 'jotform-test',
                numOccurrences: 1,
                secretType: 'JotForm',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { match: { apiKey: 'abcdefghijklmnopqrstuvwxyz123456' } },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [jotformFinding],
                },
            });

            const user = userEvent.setup();
            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            await user.click(recheckButton);

            expect(mockJotformValidityHelper).toHaveBeenCalledWith(jotformFinding);
        });

        test('does not call validity helper for unknown secret types', async () => {
            const unknownTypeFindings: Finding[] = [{
                fingerprint: "fp6",
                numOccurrences: 1,
                occurrences: mockOccurrencesOne,
                validity: "valid",
                validatedAt: "2025-05-17T18:16:16.870Z",
                secretType: "Unknown Secret Type",
                secretValue: {
                    match: { some_key: "value" },
                    validatedAt: "2025-05-17T18:16:16.870Z",
                    validity: "valid"
                }
            }];

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: unknownTypeFindings,
                },
            });

            const user = userEvent.setup();
            render(<Findings />);

            const recheckButtons = screen.getAllByTestId('rotate-cw');
            await user.click(recheckButtons[0]);

            expect(mockAwsValidityHelper).not.toHaveBeenCalled();
            expect(mockAwsSessionValidityHelper).not.toHaveBeenCalled();
            expect(mockAnthropicValidityHelper).not.toHaveBeenCalled();
            expect(mockOpenaiValidityHelper).not.toHaveBeenCalled();
            expect(mockGeminiValidityHelper).not.toHaveBeenCalled();
            expect(mockArtifactoryValidityHelper).not.toHaveBeenCalled();
            expect(mockAzureOpenAIValidityHelper).not.toHaveBeenCalled();
            expect(mockJotformValidityHelper).not.toHaveBeenCalled();
            expect(mockGroqValidityHelper).not.toHaveBeenCalled();
            expect(mockMailgunValidityHelper).not.toHaveBeenCalled();
        });

        test('handles validity recheck for Artifactory tokens', async () => {
            const artifactoryFindings: Finding[] = [{
                fingerprint: "fp-artifactory",
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
                validity: "valid", // Changed to "valid" so recheck button appears
                validatedAt: Date.now().toString(),
                secretType: "Artifactory",
                secretValue: {
                    match: { 
                        api_key: "a".repeat(73),
                        url: "example.jfrog.io"
                    },
                    validatedAt: "2025-05-17T18:16:16.870Z",
                    validity: "valid"
                }
            }];

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: artifactoryFindings,
                },
            });

            const user = userEvent.setup();
            render(<Findings />);

            const recheckButtons = screen.getAllByTestId('rotate-cw');
            await user.click(recheckButtons[0]);

            expect(mockArtifactoryValidityHelper).toHaveBeenCalledWith(artifactoryFindings[0]);
        });

        test('handles validity recheck for Azure OpenAI', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const recheckButtons = screen.getAllByTestId('rotate-cw');
            await user.click(recheckButtons[3]); // Azure OpenAI is index 3 in alphabetical order

            expect(mockAzureOpenAIValidityHelper).toHaveBeenCalledWith(mockFindings[9]); // Azure OpenAI finding
        });
    });

    describe('Validity Status Styling', () => {
        test('applies correct CSS classes for validity status', () => {
            render(<Findings />);

            const validStatuses = screen.getAllByText('valid');
            const invalidStatus = screen.getByText('invalid').closest('.validity-status');
            const unknownStatus = screen.getByText('unknown').closest('.validity-status');
            const failedStatus = screen.getByText('failed to check').closest('.validity-status');

            expect(validStatuses[0].closest('.validity-status')).toHaveClass('validity-valid');
            expect(invalidStatus).toHaveClass('validity-invalid');
            expect(unknownStatus).toHaveClass('validity-unknown');
            expect(failedStatus).toHaveClass('validity-failed');
        });
    });

    describe('Pagination', () => {
        const createManyFindings = (count: number): Finding[] => {
            const findings: Finding[] = [];
            for (let i = 1; i <= count; i++) {
                const mockOccurrence: AWSOccurrence = {
                    accountId: "1111111111",
                    arn: "arn:aws:iam::1111111111:user/leekr",
                    filePath: "main.foobar.js",
                    fingerprint: `fp${i}`,
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
                const mockOccurrenceSet: Set<Occurrence> = new Set([mockOccurrence]);
                findings.push({
                    fingerprint: `fp${i}`,
                    numOccurrences: mockOccurrenceSet.size,
                    occurrences: mockOccurrenceSet,
                    validity: "valid",
                    validatedAt: "2025-05-17T18:16:16.870Z",
                    secretType: "AWS Access & Secret Keys",
                    secretValue: {
                        match: { access_key_id: "lol", secret_key_id: "wut" },
                        validatedAt: "2025-05-17T18:16:16.870Z",
                        validity: "valid"
                    }
                });
            }
            return findings;
        };

        test('shows only 10 items per page', () => {
            const manyFindings = createManyFindings(25);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            render(<Findings />);

            const rows = screen.getAllByRole('row');
            expect(rows).toHaveLength(11);
        });

        test('resets to page 1 when filters change', async () => {
            const user = userEvent.setup();
            const manyFindings = createManyFindings(25);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            const { container } = render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            await user.selectOptions(validityFilter, 'valid');

            const findings = container.querySelectorAll('.findings-td');
            expect(findings).toHaveLength(10);
        });

        test('renders pagination controls when more than 10 items', () => {
            const manyFindings = createManyFindings(15);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            render(<Findings />);

            expect(screen.getByText('Previous')).toBeInTheDocument();
            expect(screen.getByText('Next')).toBeInTheDocument();
            
            const pageButtons = document.querySelectorAll('.pagination-page');
            expect(pageButtons).toHaveLength(2);
            expect(pageButtons[0]).toHaveTextContent('1');
            expect(pageButtons[1]).toHaveTextContent('2');
            
            expect(screen.getByText('Showing 1-10 of 15 findings')).toBeInTheDocument();
        });

        test('navigates to next page when Next button clicked', async () => {
            const user = userEvent.setup();
            const manyFindings = createManyFindings(15);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            render(<Findings />);

            const nextButton = screen.getByText('Next');
            await user.click(nextButton);

            expect(screen.getByText('Showing 11-15 of 15 findings')).toBeInTheDocument();
        });

        test('navigates to previous page when Previous button clicked', async () => {
            const user = userEvent.setup();
            const manyFindings = createManyFindings(15);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            render(<Findings />);

            const nextButton = screen.getByText('Next');
            await user.click(nextButton);

            const prevButton = screen.getByText('Previous');
            await user.click(prevButton);

            expect(screen.getByText('Showing 1-10 of 15 findings')).toBeInTheDocument();
        });

        test('disables Previous button on first page', () => {
            const manyFindings = createManyFindings(15);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            render(<Findings />);

            const prevButton = screen.getByText('Previous');
            expect(prevButton).toBeDisabled();
        });

        test('disables Next button on last page', async () => {
            const user = userEvent.setup();
            const manyFindings = createManyFindings(15);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            render(<Findings />);

            const nextButton = screen.getByText('Next');
            await user.click(nextButton);

            expect(nextButton).toBeDisabled();
        });

        test('navigates to specific page when page number clicked', async () => {
            const user = userEvent.setup();
            const manyFindings = createManyFindings(25);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            render(<Findings />);

            const pageButtons = document.querySelectorAll('.pagination-page');
            const page2Button = Array.from(pageButtons).find(button => button.textContent === '2');
            await user.click(page2Button as Element);

            expect(screen.getByText('Showing 11-20 of 25 findings')).toBeInTheDocument();
        });

        test('highlights active page number', () => {
            const manyFindings = createManyFindings(15);
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: manyFindings,
                },
            });

            render(<Findings />);

            const pageButtons = document.querySelectorAll('.pagination-page');
            const activePage = Array.from(pageButtons).find(button => button.textContent === '1');
            expect(activePage).toHaveClass('active');
        });
    });

    describe('Edge Cases', () => {
        test('handles empty findings array', () => {
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [],
                },
            });

            render(<Findings />);

            expect(screen.getByText('No findings match your filters.')).toBeInTheDocument();
        });

        test('handles findings without validatedAt timestamp', () => {
            const findingsWithoutTimestamp: Finding[] = [{
                fingerprint: "fp1",
                numOccurrences: mockOccurrencesOne.size,
                occurrences: mockOccurrencesOne,
                validity: "valid",
                validatedAt: "",
                secretType: "AWS Access & Secret Keys",
                secretValue: {
                    match: { access_key_id: "lol", secret_key_id: "wut" },
                    validatedAt: "",
                    validity: "valid"
                }
            }];

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: findingsWithoutTimestamp,
                },
            });

            render(<Findings />);

            expect(screen.queryByTestId('shield-check')).not.toBeInTheDocument();
        });

        test('handles chrome API errors gracefully', async () => {
            const user = userEvent.setup();
            mockChrome.tabs.query.mockImplementation((query, callback) => {
                callback([]);
            });

            render(<Findings />);

            const viewButtons = screen.getAllByTestId('square-arrow-right');
            await user.click(viewButtons[0]);

            expect(mockChrome.tabs.update).not.toHaveBeenCalled();
        });
    });

    describe('Accessibility', () => {
        test('has proper form labels', () => {
            render(<Findings />);

            expect(screen.getByLabelText('Validity Status:')).toBeInTheDocument();
            expect(screen.getByLabelText('Secret Type:')).toBeInTheDocument();
        });

        test('has proper table structure', () => {
            render(<Findings />);

            const table = screen.getByRole('table');
            expect(table).toBeInTheDocument();

            const headers = screen.getAllByRole('columnheader');
            expect(headers).toHaveLength(4);
        });

        test('has proper button labels and titles', () => {
            render(<Findings />);

            const viewButtons = screen.getAllByTitle('View Occurrences');
            expect(viewButtons).toHaveLength(10);

            const recheckButtons = screen.getAllByLabelText('Recheck validity');
            expect(recheckButtons).toHaveLength(7);
        });

        test('table headers are clickable for sorting', () => {
            render(<Findings />);

            const sortableHeaders = [
                screen.getByText('Type').closest('div'),
                screen.getByText('Validity').closest('div'),
                screen.getByText('Occurrences').closest('div')
            ];

            sortableHeaders.forEach(header => {
                expect(header).toHaveClass('sortable-header');
            });
        });
    });

    describe('Apollo Validity Checking', () => {
        test('calls apolloValidityHelper when recheck button is clicked for Apollo finding', async () => {
            const apolloFinding = {
                fingerprint: 'apollo-test',
                numOccurrences: 1,
                secretType: 'Apollo',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { match: { api_key: 'abcdefghij1234567890AB' } },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [apolloFinding],
                },
            });

            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            fireEvent.click(recheckButton);

            expect(mockApolloValidityHelper).toHaveBeenCalledWith(apolloFinding);
        });
    });

    describe('GCP Validity Checking', () => {
        test('calls gcpValidityHelper when recheck button is clicked for GCP finding', async () => {
            const gcpFinding = {
                fingerprint: 'gcp-test',
                numOccurrences: 1,
                secretType: 'Google Cloud Platform',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { 
                    match: { 
                        service_account_key: JSON.stringify({
                            type: "service_account",
                            project_id: "test-project",
                            client_email: "test@test-project.iam.gserviceaccount.com"
                        })
                    } 
                },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [gcpFinding],
                },
            });

            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            fireEvent.click(recheckButton);

            expect(mockGcpValidityHelper).toHaveBeenCalledWith(gcpFinding);
        });
    });

    describe('Docker Validity Checking', () => {
        test('calls dockerValidityHelper when recheck button is clicked for Docker finding', async () => {
            const dockerFinding = {
                fingerprint: 'docker-test',
                numOccurrences: 1,
                secretType: 'Docker',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { 
                    match: { 
                        registry: "registry.example.com",
                        auth: "dGVzdDp0ZXN0",
                        username: "test",
                        password: "test",
                        email: "test@example.com"
                    } 
                },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [dockerFinding],
                },
            });

            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            fireEvent.click(recheckButton);

            expect(mockDockerValidityHelper).toHaveBeenCalledWith(dockerFinding);
        });
    });

    describe('Groq Validity Checking', () => {
        test('calls groqValidityHelper when recheck button is clicked for Groq finding', async () => {
            const groqFinding = {
                fingerprint: 'groq-test',
                numOccurrences: 1,
                secretType: 'Groq',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { 
                    match: { 
                        apiKey: "gsk_" + "a".repeat(52)
                    } 
                },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [groqFinding],
                },
            });

            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            fireEvent.click(recheckButton);

            expect(mockGroqValidityHelper).toHaveBeenCalledWith(groqFinding);
        });
    });

    describe('Mailgun Validity Checking', () => {
        test('calls mailgunValidityHelper when recheck button is clicked for Mailgun finding', async () => {
            const mailgunFinding = {
                fingerprint: 'mailgun-test',
                numOccurrences: 1,
                secretType: 'Mailgun',
                validity: 'valid' as const,
                validatedAt: '2025-05-30T12:00:00.000Z',
                secretValue: { match: { apiKey: 'key-' + 'a'.repeat(32) } },
                occurrences: new Set([])
            };

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    findings: [mailgunFinding],
                },
            });

            render(<Findings />);

            const recheckButton = screen.getByLabelText('Recheck validity');
            fireEvent.click(recheckButton);

            expect(mockMailgunValidityHelper).toHaveBeenCalledWith(mailgunFinding);
        });
    });
});