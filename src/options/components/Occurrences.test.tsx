import { fireEvent, render, screen } from '@testing-library/react';
import { useAppContext } from '../../popup/AppContext';
import { AWSOccurrence } from '../../types/aws.types';
import { Finding, Occurrence } from '../../types/findings.types';
import { awsValidityHelper } from '../../utils/validators/aws_access_keys/awsValidityHelper';
import { Occurrences } from './Occurrences';

jest.mock('../../popup/AppContext', () => ({
    useAppContext: jest.fn()
}));

jest.mock('../../utils/validators/aws_access_keys/awsValidityHelper');

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

const mockOccurrences: Set<Occurrence> = new Set([mockOccurrence]);

const mockFindings: Finding[] = [{
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
}]

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

        expect(screen.getByText(mockOccurrence.sourceContent.contentStartLineNum + 1)).toBeInTheDocument(); // first line number
        expect(screen.getByText(mockOccurrence.sourceContent.contentEndLineNum + 1)).toBeInTheDocument(); // last line number
    });

    test('calls awsValidityHelper on recheck button click', () => {
        render(<Occurrences filterFingerprint='fp1' />);

        const recheckButton = screen.getByLabelText('Recheck validity');
        fireEvent.click(recheckButton);

        expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[0]);
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
