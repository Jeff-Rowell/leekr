import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AWSOccurrence } from 'src/types/aws.types';
import { AnthropicOccurrence } from 'src/types/anthropic';
import { OpenAIOccurrence } from 'src/types/openai';
import { GeminiOccurrence } from 'src/types/gemini';
import { HuggingFaceOccurrence } from 'src/types/huggingface';
import { ArtifactoryOccurrence } from 'src/types/artifactory';
import { AzureOpenAIOccurrence } from 'src/types/azure_openai';
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
        expect(shieldIcons.length).toBe(11);
    });

    test('opens settings menu when settings button is clicked', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        expect(settingsButtons.length).toBe(11);
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
        expect(recheckButtons).toHaveLength(11);

        fireEvent.click(recheckButtons[0]);
        expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[0]);
    });

    test('calls awsSessionValidityHelper when recheck button is clicked for AWS Session Keys', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(11);

        fireEvent.click(recheckButtons[4]);
        expect(awsSessionValidityHelper).toHaveBeenCalledWith(mockFindings[4]);
    });

    test('calls anthropicValidityHelper when recheck button is clicked for Anthropic AI', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(11);

        fireEvent.click(recheckButtons[5]);
        expect(anthropicValidityHelper).toHaveBeenCalledWith(mockFindings[5]);
    });

    test('calls openaiValidityHelper when recheck button is clicked for OpenAI', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(11);

        fireEvent.click(recheckButtons[6]);
        expect(openaiValidityHelper).toHaveBeenCalledWith(mockFindings[6]);
    });

    test('calls geminiValidityHelper when recheck button is clicked for Gemini', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(11);

        fireEvent.click(recheckButtons[7]);
        expect(geminiValidityHelper).toHaveBeenCalledWith(mockFindings[7]);
    });

    test('calls huggingfaceValidityHelper when recheck button is clicked for Hugging Face', async () => {
        render(<FindingsTab />);

        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(11);

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

    test('handles sendMessage rejection in useEffect catch block', () => {
        const mockError = new Error('Connection failed');
        (chrome.runtime.sendMessage as jest.Mock).mockReturnValue(Promise.reject(mockError));

        render(<FindingsTab />);

        expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
        expect(chrome.storage.local.set).toHaveBeenCalledWith({ "notifications": '' }, expect.any(Function));
        expect(chrome.runtime.sendMessage).toHaveBeenCalledWith({
            type: 'CLEAR_NOTIFICATIONS',
            payload: ''
        });
    });

    test('calls artifactoryValidityHelper for Artifactory findings', async () => {
        render(<FindingsTab />);
        
        // Find the Artifactory recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(11);
        
        // Click the Artifactory recheck button (10th button, index 9) 
        fireEvent.click(recheckButtons[9]);
        
        // Verify artifactory validity helper was called
        expect(artifactoryValidityHelper).toHaveBeenCalledWith(mockFindings[9]);
    });

    test('calls azureOpenAIValidityHelper for Azure OpenAI findings', async () => {
        render(<FindingsTab />);
        
        // Find the Azure OpenAI recheck button directly (in the validity tooltip)
        const recheckButtons = screen.getAllByLabelText('Recheck validity');
        expect(recheckButtons).toHaveLength(11);
        
        // Click the last recheck button (Azure OpenAI finding)
        fireEvent.click(recheckButtons[10]);
        
        // Verify azure openai validity helper was called
        expect(azureOpenAIValidityHelper).toHaveBeenCalledWith(mockFindings[10]);
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
});