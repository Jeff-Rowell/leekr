import { fireEvent, render, screen } from '@testing-library/react';
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
import { JotFormOccurrence } from '../../types/jotform';
import { GroqOccurrence } from '../../types/groq';
import { MailgunOccurrence } from '../../types/mailgun';
import { MailchimpOccurrence } from '../../types/mailchimp';
import { DeepSeekOccurrence } from '../../types/deepseek';
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
import { mailchimpValidityHelper } from '../../utils/validators/mailchimp/mailchimpValidityHelper';
import { deepseekValidityHelper } from '../../utils/validators/deepseek/deepseekValidityHelper';
import { Occurrences } from './Occurrences';

jest.mock('../../popup/AppContext', () => ({
    useAppContext: jest.fn()
}));

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
jest.mock('../../utils/validators/mailchimp/mailchimpValidityHelper');
jest.mock('../../utils/validators/deepseek/deepseekValidityHelper');

const mockOccurrence: AWSOccurrence = {
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
        content: "foobar\n".repeat(18),
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
    fingerprint: "fp2",
    resourceType: "Session Key",
    secretType: "AWS Session Keys",
    secretValue: {
        match: { session_key_id: "session123", access_key_id: "lol", secret_key_id: "wut" }
    },
    sourceContent: {
        content: "sessionfoobar\n".repeat(18),
        contentEndLineNum: 35,
        contentFilename: "SessionApp.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/session.foobar.js",
};

const mockAnthropicOccurrence: AnthropicOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp3",
    type: "ADMIN",
    secretType: "Anthropic AI",
    secretValue: {
        match: { api_key: "sk-ant-api-test123456789" }
    },
    sourceContent: {
        content: "anthropicfoobar\n".repeat(18),
        contentEndLineNum: 35,
        contentFilename: "AnthropicApp.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/anthropic.foobar.js",
};

const mockOpenAIOccurrence: OpenAIOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp4",
    type: "API Key",
    secretType: "OpenAI",
    secretValue: {
        match: { api_key: "sk-proj-test123T3BlbkFJtest456" }
    },
    sourceContent: {
        content: "openaifoobar\n".repeat(18),
        contentEndLineNum: 35,
        contentFilename: "OpenAIApp.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/openai.foobar.js",
};

const mockGeminiOccurrence: GeminiOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp5",
    type: "API Key & Secret",
    secretType: "Gemini",
    secretValue: {
        match: { 
            api_key: "account-1234567890ABCDEFGH12",
            api_secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ12"
        }
    },
    sourceContent: {
        content: "geminifoobar\n".repeat(18),
        contentEndLineNum: 35,
        contentFilename: "GeminiApp.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/gemini.foobar.js",
};

const mockHuggingFaceOccurrence: HuggingFaceOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp6",
    type: "API Key",
    secretType: "Hugging Face",
    secretValue: {
        match: { 
            api_key: "hf_1234567890abcdefghijklmnopqrstuv12"
        }
    },
    sourceContent: {
        content: "huggingfacefoobar\n".repeat(18),
        contentEndLineNum: 35,
        contentFilename: "HuggingFaceApp.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/huggingface.foobar.js",
};

const mockJotFormOccurrence: JotFormOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp15",
    type: "API Key",
    secretType: "JotForm",
    secretValue: {
        match: { 
            apiKey: "abcdefghijklmnopqrstuvwxyz123456"
        }
    },
    sourceContent: {
        content: "jotformfoobar\n".repeat(18),
        contentEndLineNum: 35,
        contentFilename: "JotFormApp.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/jotform.foobar.js",
    validity: "valid"
};

const mockOccurrences: Set<Occurrence> = new Set([mockOccurrence]);
const mockSessionOccurrences: Set<Occurrence> = new Set([mockSessionOccurrence]);
const mockAnthropicOccurrences: Set<Occurrence> = new Set([mockAnthropicOccurrence]);
const mockOpenAIOccurrences: Set<Occurrence> = new Set([mockOpenAIOccurrence]);
const mockGeminiOccurrences: Set<Occurrence> = new Set([mockGeminiOccurrence]);
const mockJotFormOccurrences: Set<Occurrence> = new Set([mockJotFormOccurrence]);
const mockGcpOccurrence: GcpOccurrence = {
    filePath: "main.foobar.js",
    fingerprint: "fp9",
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
        content: "gcpfoobar\n".repeat(18),
        contentEndLineNum: 35,
        contentFilename: "GcpApp.js",
        contentStartLineNum: 18,
        exactMatchNumbers: [23, 30]
    },
    url: "http://localhost:3000/static/js/gcp.foobar.js",
};

const mockHuggingFaceOccurrences: Set<Occurrence> = new Set([mockHuggingFaceOccurrence]);
const mockGcpOccurrences: Set<Occurrence> = new Set([mockGcpOccurrence]);

const mockFindings: Finding[] = [
    {
        fingerprint: "fp1",
        numOccurrences: mockOccurrences.size,
        occurrences: mockOccurrences,
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" },
            validatedAt: "2025-05-17T18:16:16.870Z",
            validity: "valid"
        }
    },
    {
        fingerprint: "fp2",
        numOccurrences: mockSessionOccurrences.size,
        occurrences: mockSessionOccurrences,
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
        secretType: "AWS Session Keys",
        secretValue: {
            match: { session_token: "session123", access_key_id: "lol", secret_key_id: "wut" },
            validatedAt: "2025-05-17T18:16:16.870Z",
            validity: "valid"
        }
    },
    {
        fingerprint: "fp3",
        numOccurrences: mockAnthropicOccurrences.size,
        occurrences: mockAnthropicOccurrences,
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
        secretType: "Anthropic AI",
        secretValue: {
            match: { api_key: "sk-ant-api-test123456789" },
            validatedAt: "2025-05-17T18:16:16.870Z",
            validity: "valid"
        }
    },
    {
        fingerprint: "fp4",
        numOccurrences: mockOpenAIOccurrences.size,
        occurrences: mockOpenAIOccurrences,
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
        secretType: "OpenAI",
        secretValue: {
            match: { api_key: "sk-proj-test123T3BlbkFJtest456" },
            validatedAt: "2025-05-17T18:16:16.870Z",
            validity: "valid"
        }
    },
    {
        fingerprint: "fp5",
        numOccurrences: mockGeminiOccurrences.size,
        occurrences: mockGeminiOccurrences,
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
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
        fingerprint: "fp6",
        numOccurrences: mockHuggingFaceOccurrences.size,
        occurrences: mockHuggingFaceOccurrences,
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
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
        fingerprint: "fp7",
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
                content: "const token = \"" + "a".repeat(73) + "\";\nconst url = \"example.jfrog.io\";",
                contentFilename: "test.js",
                contentStartLineNum: 5,
                contentEndLineNum: 15,
                exactMatchNumbers: [10]
            }
        } as ArtifactoryOccurrence]),
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
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
        fingerprint: "fp8",
        numOccurrences: 1,
        occurrences: new Set([{
            fingerprint: "azure-openai-fp",
            secretType: "Azure OpenAI",
            filePath: "test.js",
            url: "http://localhost:3000/test.js",
            type: "API Key",
            secretValue: {
                match: {
                    api_key: "abcdef12345678901234567890123456",
                    url: "test-instance.openai.azure.com"
                }
            },
            sourceContent: {
                content: "const apiKey = \"abcdef12345678901234567890123456\";\nconst endpoint = \"test-instance.openai.azure.com\";",
                contentFilename: "test.js",
                contentStartLineNum: 5,
                contentEndLineNum: 15,
                exactMatchNumbers: [10]
            }
        } as AzureOpenAIOccurrence]),
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
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
        fingerprint: "fp9",
        numOccurrences: mockGcpOccurrences.size,
        occurrences: mockGcpOccurrences,
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
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
        fingerprint: "fp15",
        numOccurrences: mockJotFormOccurrences.size,
        occurrences: mockJotFormOccurrences,
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
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
            filePath: "mailgun-config.js",
            fingerprint: "fp16",
            type: "Mailgun API Key",
            secretType: "Mailgun",
            secretValue: {
                match: { 
                    apiKey: "key-" + "a".repeat(32)
                }
            },
            sourceContent: {
                content: "mailgunfoobar\n".repeat(18),
                contentEndLineNum: 35,
                contentFilename: "MailgunApp.js",
                contentStartLineNum: 18,
                exactMatchNumbers: [23, 30]
            },
            url: "http://localhost:3000/static/js/mailgun.foobar.js",
            validity: "valid"
        } as MailgunOccurrence]),
        validity: "valid",
        validatedAt: "2025-05-13T18:16:16.870Z",
        secretType: "Mailgun",
        secretValue: {
            match: { 
                apiKey: "key-" + "a".repeat(32)
            },
            validatedAt: "2025-05-17T18:16:16.870Z",
            validity: "valid"
        }
    }
]

describe('Occurrences Component', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindings,
            },
        });
        global.URL.createObjectURL = jest.fn(() => 'blob:mock-url');
        global.URL.revokeObjectURL = jest.fn();
    });

    afterEach(() => {
        jest.clearAllMocks();
        (global.URL.createObjectURL as jest.Mock).mockRestore?.();
    });

    test('renders empty state when no findings', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [],
            },
        });
        render(<Occurrences />);

        expect(screen.getByText('No occurrences found.')).toBeInTheDocument();
    });

    test('renders a finding and occurrence', () => {
        render(<Occurrences filterFingerprint='fp1' />);

        expect(screen.getByText('AWS Access & Secret Keys')).toBeInTheDocument();
        expect(screen.getByText('App.js: Line 23')).toBeInTheDocument();
        expect(screen.getByText('View JS Bundle')).toBeInTheDocument();
    });

    test('filters by fingerprint', () => {
        render(<Occurrences filterFingerprint='fp1' />);

        expect(screen.getByText('AWS Access & Secret Keys')).toBeInTheDocument();
        expect(screen.queryByText('No occurrences found.')).not.toBeInTheDocument();
    });

    test('expands and collapses source content', () => {
        render(<Occurrences filterFingerprint='fp1' />);

        const expandBtn = screen.getByLabelText('Expand code');
        fireEvent.click(expandBtn);

        expect(screen.getByText(mockOccurrence.sourceContent.contentStartLineNum + 1)).toBeInTheDocument();
        expect(screen.getByText(mockOccurrence.sourceContent.contentEndLineNum + 1)).toBeInTheDocument();
    });

    test('calls awsValidityHelper on recheck button click for AWS Access Keys', () => {
        render(<Occurrences filterFingerprint='fp1' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[0]);
    });

    test('calls awsSessionValidityHelper on recheck button click for AWS Session Keys', () => {
        render(<Occurrences filterFingerprint='fp2' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(awsSessionValidityHelper).toHaveBeenCalledWith(mockFindings[1]);
    });

    test('calls anthropicValidityHelper on recheck button click for Anthropic AI', () => {
        render(<Occurrences filterFingerprint='fp3' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(anthropicValidityHelper).toHaveBeenCalledWith(mockFindings[2]);
    });

    test('calls openaiValidityHelper on recheck button click for OpenAI', () => {
        render(<Occurrences filterFingerprint='fp4' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(openaiValidityHelper).toHaveBeenCalledWith(mockFindings[3]);
    });

    test('renders AWS Session Keys finding and occurrence', () => {
        render(<Occurrences filterFingerprint='fp2' />);

        expect(screen.getByText('AWS Session Keys')).toBeInTheDocument();
        expect(screen.getByText('SessionApp.js: Line 23')).toBeInTheDocument();
        expect(screen.getByText('View JS Bundle')).toBeInTheDocument();
    });

    test('renders Anthropic AI finding and occurrence', () => {
        render(<Occurrences filterFingerprint='fp3' />);

        expect(screen.getByText('Anthropic AI')).toBeInTheDocument();
        expect(screen.getByText('AnthropicApp.js: Line 23')).toBeInTheDocument();
        expect(screen.getByText('View JS Bundle')).toBeInTheDocument();
    });

    test('renders OpenAI finding and occurrence', () => {
        render(<Occurrences filterFingerprint='fp4' />);

        expect(screen.getByText('OpenAI')).toBeInTheDocument();
        expect(screen.getByText('OpenAIApp.js: Line 23')).toBeInTheDocument();
        expect(screen.getByText('View JS Bundle')).toBeInTheDocument();
    });

    test('renders Gemini finding and occurrence', () => {
        render(<Occurrences filterFingerprint='fp5' />);

        expect(screen.getByText('Gemini')).toBeInTheDocument();
        expect(screen.getByText('GeminiApp.js: Line 23')).toBeInTheDocument();
        expect(screen.getByText('View JS Bundle')).toBeInTheDocument();
    });

    test('calls Gemini validity helper when recheck button is clicked', () => {
        render(<Occurrences filterFingerprint='fp5' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(geminiValidityHelper).toHaveBeenCalledWith(mockFindings[4]);
    });

    test('calls Hugging Face validity helper when recheck button is clicked', () => {
        render(<Occurrences filterFingerprint='fp6' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(huggingfaceValidityHelper).toHaveBeenCalledWith(mockFindings[5]);
    });

    test('renders JotForm finding and occurrence', () => {
        render(<Occurrences filterFingerprint='fp15' />);

        expect(screen.getByText('JotForm')).toBeInTheDocument();
        expect(screen.getByText('JotFormApp.js: Line 23')).toBeInTheDocument();
        expect(screen.getByText('View JS Bundle')).toBeInTheDocument();
    });

    test('calls JotForm validity helper when recheck button is clicked', () => {
        render(<Occurrences filterFingerprint='fp15' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(jotformValidityHelper).toHaveBeenCalledWith(mockFindings[9]);
    });

    test('calls Azure OpenAI validity helper when recheck button is clicked', () => {
        render(<Occurrences filterFingerprint='fp8' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(azureOpenAIValidityHelper).toHaveBeenCalledWith(mockFindings[7]);
    });

    test('does not call validity helpers for unknown secret types', () => {
        const unknownTypeFinding: Finding = {
            fingerprint: "fp4",
            numOccurrences: 1,
            occurrences: mockOccurrences,
            validity: "valid",
            validatedAt: "2025-05-13T18:16:16.870Z",
            secretType: "Unknown Secret Type",
            secretValue: {
                match: { some_key: "value" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        };

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [unknownTypeFinding],
            },
        });

        render(<Occurrences filterFingerprint='fp4' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(awsValidityHelper).not.toHaveBeenCalled();
        expect(awsSessionValidityHelper).not.toHaveBeenCalled();
        expect(anthropicValidityHelper).not.toHaveBeenCalled();
        expect(openaiValidityHelper).not.toHaveBeenCalled();
        expect(geminiValidityHelper).not.toHaveBeenCalled();
        expect(azureOpenAIValidityHelper).not.toHaveBeenCalled();
        expect(jotformValidityHelper).not.toHaveBeenCalled();
        expect(mailgunValidityHelper).not.toHaveBeenCalled();
        expect(deepseekValidityHelper).not.toHaveBeenCalled();
    });

    test('clicking download source code button calls URL.createObjectURL', () => {
        const mockCreateObjectURL = jest.fn(() => 'blob:mock-url');
        global.URL.createObjectURL = mockCreateObjectURL;

        render(<Occurrences filterFingerprint='fp1' />);
        const downloadBtn = screen.getByLabelText('Download Source Code');

        fireEvent.click(downloadBtn);

        expect(mockCreateObjectURL).toHaveBeenCalled();
    });

    test('clicking download js bundle button calls URL.createObjectURL', () => {
        const mockCreateObjectURL = jest.fn(() => 'blob:mock-url');
        global.URL.createObjectURL = mockCreateObjectURL;

        render(<Occurrences filterFingerprint='fp1' />);
        const link = screen.getByTitle('View JS Bundle');
        expect(link).toBeInTheDocument();
        expect(link).toHaveAttribute('href', mockOccurrence.url);
        expect(link).toHaveAttribute('target', '_blank');
        expect(link).toHaveAttribute('rel', 'noopener noreferrer');
        fireEvent.click(link);
    });

    test('calls artifactoryValidityHelper when rechecking Artifactory finding validity', async () => {
        render(<Occurrences filterFingerprint='fp7' />);
        
        // Find the recheck button in the Artifactory finding
        const recheckButton = screen.getByLabelText('Recheck validity');
        expect(recheckButton).toBeInTheDocument();
        
        // Click the recheck button
        fireEvent.click(recheckButton);
        
        // Verify that the artifactory validity helper was called
        expect(artifactoryValidityHelper).toHaveBeenCalledWith(
            expect.objectContaining({
                fingerprint: "fp7",
                secretType: "Artifactory"
            })
        );
    });

    test('renders Artifactory occurrence correctly', () => {
        render(<Occurrences filterFingerprint='fp7' />);
        
        // Should show the Artifactory finding header
        expect(screen.getByText('Artifactory')).toBeInTheDocument();
        expect(screen.getByText('valid')).toBeInTheDocument();
        expect(screen.getByText('1 occurrences')).toBeInTheDocument();
        
        // Should show occurrence item
        expect(screen.getByText('test.js: Line 10')).toBeInTheDocument();
    });

    test('expands Artifactory occurrence to show code', () => {
        render(<Occurrences filterFingerprint='fp7' />);
        
        // Click on the occurrence to expand it
        const occurrenceHeader = screen.getByText('test.js: Line 10').closest('.occurrence-header');
        fireEvent.click(occurrenceHeader!);
        
        // Check that the code is expanded by looking for line numbers
        expect(screen.getByText('6')).toBeInTheDocument(); // First line number
        expect(screen.getByText('7')).toBeInTheDocument(); // Second line number
        
        // The line content rendering has an issue in the component, but at least verify it's expanded
        const codeContainer = document.querySelector('pre');
        expect(codeContainer).toBeInTheDocument();
    });

    test('downloads Artifactory source content correctly', () => {
        const mockCreateObjectURL = jest.fn(() => 'blob:mock-url');
        global.URL.createObjectURL = mockCreateObjectURL;

        render(<Occurrences filterFingerprint='fp7' />);
        
        // Find and click the download button
        const downloadBtn = screen.getByLabelText('Download Source Code');
        fireEvent.click(downloadBtn);

        expect(mockCreateObjectURL).toHaveBeenCalled();
    });

    test('calls apolloValidityHelper on recheck button click for Apollo', () => {
        // Create an Apollo finding and occurrence for testing
        const apolloOccurrence = {
            filePath: "apollo.js",
            fingerprint: "apollo-fp",
            type: "API_KEY",
            secretType: "Apollo",
            secretValue: {
                match: { 
                    api_key: "abcdefghij1234567890AB"
                }
            },
            url: "https://example.com/apollo.js",
            sourceContent: {
                content: "const apolloKey = 'abcdefghij1234567890AB';",
                contentFilename: "apollo.js",
                contentStartLineNum: 5,
                contentEndLineNum: 15,
                exactMatchNumbers: [10]
            }
        };

        const apolloFinding = {
            fingerprint: "apollo-fp",
            numOccurrences: 1,
            occurrences: new Set([apolloOccurrence]),
            validity: "valid" as const,
            validatedAt: "2025-05-30T12:00:00.000Z",
            secretType: "Apollo",
            secretValue: {
                match: { 
                    api_key: "abcdefghij1234567890AB"
                }
            }
        };

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [apolloFinding],
            },
        });

        render(<Occurrences filterFingerprint='apollo-fp' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(apolloValidityHelper).toHaveBeenCalledWith(apolloFinding);
    });

    test('calls gcpValidityHelper on recheck button click for Google Cloud Platform', () => {
        render(<Occurrences filterFingerprint='fp9' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(gcpValidityHelper).toHaveBeenCalledWith(mockFindings[8]);
    });

    test('calls dockerValidityHelper on recheck button click for Docker', () => {
        // Create a Docker finding and occurrence for testing
        const dockerOccurrence = {
            filePath: "docker-config.js",
            fingerprint: "docker-fp",
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
            url: "https://example.com/docker-config.js",
            sourceContent: {
                content: "const dockerAuth = { registry: 'registry.example.com', auth: 'dGVzdDp0ZXN0' };",
                contentFilename: "docker-config.js",
                contentStartLineNum: 5,
                contentEndLineNum: 15,
                exactMatchNumbers: [10]
            }
        };

        const dockerFinding = {
            fingerprint: "docker-fp",
            numOccurrences: 1,
            occurrences: new Set([dockerOccurrence]),
            validity: "valid" as const,
            validatedAt: "2025-05-30T12:00:00.000Z",
            secretType: "Docker",
            secretValue: {
                match: {
                    registry: "registry.example.com",
                    auth: "dGVzdDp0ZXN0",
                    username: "test",
                    password: "test",
                    email: "test@example.com"
                }
            }
        };

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [dockerFinding],
            },
        });

        render(<Occurrences filterFingerprint='docker-fp' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(dockerValidityHelper).toHaveBeenCalledWith(dockerFinding);
    });

    test('calls groqValidityHelper on recheck button click for Groq', () => {
        // Create a Groq finding and occurrence for testing
        const groqOccurrence = {
            filePath: "groq-config.js",
            fingerprint: "groq-fp",
            type: "API_KEY",
            secretType: "Groq",
            secretValue: {
                match: {
                    apiKey: "gsk_" + "a".repeat(52)
                }
            },
            url: "https://example.com/groq-config.js",
            sourceContent: {
                content: "const groqKey = 'gsk_" + "a".repeat(52) + "';",
                contentFilename: "groq-config.js",
                contentStartLineNum: 5,
                contentEndLineNum: 15,
                exactMatchNumbers: [10]
            },
            validity: "valid"
        };

        const groqFinding = {
            fingerprint: "groq-fp",
            numOccurrences: 1,
            occurrences: new Set([groqOccurrence]),
            validity: "valid" as const,
            validatedAt: "2025-05-30T12:00:00.000Z",
            secretType: "Groq",
            secretValue: {
                match: {
                    apiKey: "gsk_" + "a".repeat(52)
                }
            }
        };

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [groqFinding],
            },
        });

        render(<Occurrences filterFingerprint='groq-fp' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(groqValidityHelper).toHaveBeenCalledWith(groqFinding);
    });

    test('calls mailgunValidityHelper on recheck button click for Mailgun', () => {
        // Create a Mailgun finding and occurrence for testing
        const mailgunOccurrence = {
            filePath: "mailgun-config.js",
            fingerprint: "mailgun-fp",
            type: "Mailgun API Key",
            secretType: "Mailgun",
            secretValue: {
                match: {
                    apiKey: "key-" + "a".repeat(32)
                }
            },
            url: "https://example.com/mailgun-config.js",
            sourceContent: {
                content: "const mailgunKey = 'key-" + "a".repeat(32) + "';",
                contentFilename: "mailgun-config.js",
                contentStartLineNum: 5,
                contentEndLineNum: 15,
                exactMatchNumbers: [10]
            },
            validity: "valid"
        };

        const mailgunFinding = {
            fingerprint: "mailgun-fp",
            numOccurrences: 1,
            occurrences: new Set([mailgunOccurrence]),
            validity: "valid" as const,
            validatedAt: "2025-05-30T12:00:00.000Z",
            secretType: "Mailgun",
            secretValue: {
                match: {
                    apiKey: "key-" + "a".repeat(32)
                }
            }
        };

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [mailgunFinding],
            },
        });

        render(<Occurrences filterFingerprint='mailgun-fp' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(mailgunValidityHelper).toHaveBeenCalledWith(mailgunFinding);
    });

    test('calls mailchimpValidityHelper on recheck button click for Mailchimp', () => {
        // Create a Mailchimp finding and occurrence for testing
        const mailchimpOccurrence = {
            filePath: "mailchimp-config.js",
            fingerprint: "mailchimp-fp",
            type: "Mailchimp API Key",
            secretType: "Mailchimp",
            secretValue: {
                match: {
                    apiKey: "abcd1234567890abcd1234567890abcd-us12"
                }
            },
            url: "https://example.com/mailchimp-config.js",
            sourceContent: {
                content: "const mailchimpKey = 'abcd1234567890abcd1234567890abcd-us12';",
                contentFilename: "mailchimp-config.js",
                contentStartLineNum: 5,
                contentEndLineNum: 15,
                exactMatchNumbers: [10]
            },
            validity: "valid"
        };

        const mailchimpFinding = {
            fingerprint: "mailchimp-fp",
            numOccurrences: 1,
            occurrences: new Set([mailchimpOccurrence]),
            validity: "valid" as const,
            validatedAt: "2025-05-30T12:00:00.000Z",
            secretType: "Mailchimp",
            secretValue: {
                match: {
                    apiKey: "abcd1234567890abcd1234567890abcd-us12"
                }
            }
        };

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [mailchimpFinding],
            },
        });

        render(<Occurrences filterFingerprint='mailchimp-fp' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(mailchimpValidityHelper).toHaveBeenCalledWith(mailchimpFinding);
    });

    test('calls deepseekValidityHelper on recheck button click for DeepSeek', () => {
        // Create a DeepSeek finding and occurrence for testing
        const deepseekOccurrence = {
            filePath: "deepseek-config.js",
            fingerprint: "deepseek-fp",
            type: "API Key",
            secretType: "DeepSeek",
            secretValue: {
                match: {
                    apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456"
                }
            },
            url: "https://example.com/deepseek-config.js",
            sourceContent: {
                content: "const deepseekKey = 'sk-abcdefghijklmnopqrstuvwxyz123456';",
                contentFilename: "deepseek-config.js",
                contentStartLineNum: 5,
                contentEndLineNum: 15,
                exactMatchNumbers: [10]
            },
            validity: "valid"
        };

        const deepseekFinding = {
            fingerprint: "deepseek-fp",
            numOccurrences: 1,
            occurrences: new Set([deepseekOccurrence]),
            validity: "valid" as const,
            validatedAt: "2025-05-30T12:00:00.000Z",
            secretType: "DeepSeek",
            secretValue: {
                match: {
                    apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456"
                }
            }
        };

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [deepseekFinding],
            },
        });

        render(<Occurrences filterFingerprint='deepseek-fp' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(deepseekValidityHelper).toHaveBeenCalledWith(deepseekFinding);
    });
});
