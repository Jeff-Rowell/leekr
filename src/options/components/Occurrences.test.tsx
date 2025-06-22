import { fireEvent, render, screen } from '@testing-library/react';
import { useAppContext } from '../../popup/AppContext';
import { AWSOccurrence } from '../../types/aws.types';
import { AnthropicOccurrence } from '../../types/anthropic';
import { OpenAIOccurrence } from '../../types/openai';
import { Finding, Occurrence } from '../../types/findings.types';
import { awsValidityHelper } from '../../utils/validators/aws/aws_access_keys/awsValidityHelper';
import { awsSessionValidityHelper } from '../../utils/validators/aws/aws_session_keys/awsValidityHelper';
import { anthropicValidityHelper } from '../../utils/validators/anthropic/anthropicValidityHelper';
import { openaiValidityHelper } from '../../utils/validators/openai/openaiValidityHelper';
import { Occurrences } from './Occurrences';

jest.mock('../../popup/AppContext', () => ({
    useAppContext: jest.fn()
}));

jest.mock('../../utils/validators/aws/aws_access_keys/awsValidityHelper');
jest.mock('../../utils/validators/aws/aws_session_keys/awsValidityHelper');
jest.mock('../../utils/validators/anthropic/anthropicValidityHelper');
jest.mock('../../utils/validators/openai/openaiValidityHelper');

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

const mockOccurrences: Set<Occurrence> = new Set([mockOccurrence]);
const mockSessionOccurrences: Set<Occurrence> = new Set([mockSessionOccurrence]);
const mockAnthropicOccurrences: Set<Occurrence> = new Set([mockAnthropicOccurrence]);
const mockOpenAIOccurrences: Set<Occurrence> = new Set([mockOpenAIOccurrence]);

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
});
