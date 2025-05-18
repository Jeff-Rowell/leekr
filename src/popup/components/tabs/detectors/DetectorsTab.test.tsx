import { render, screen, fireEvent } from '@testing-library/react';
import DetectorsTab from './DetectorsTab';
import { useAppContext } from '../../../AppContext';
import { Pattern } from 'src/types/patterns.types';
import { Occurrence } from 'src/types/findings.types';
import { AWSOccurrence } from 'src/types/aws.types';
import { Finding } from 'src/types/findings.types';

jest.mock('./style.css', () => ({}));

jest.mock('../../../AppContext', () => ({
    useAppContext: jest.fn(),
}));

jest.mock('lucide-react', () => ({
    SquareArrowRight: () => <div data-testid="square-arrow-right-icon" />,
}));

global.chrome = {
    runtime: {
        getURL: jest.fn((path) => `chrome-extension://extension-id/${path}`),
    },
    tabs: {
        create: jest.fn(),
    },
} as any;

describe('DetectorsTab', () => {
    const mockPatterns = {
        "AWS Access Key": {
            name: "AWS Access Key",
            familyName: "AWS Access & Secret Keys",
            pattern: /\b((?:AKIA|ABIA|ACCA|AIDA)[A-Z0-9]{16})\b/g,
            entropy: 3.0,
            isValidityCustomizable: false,
            hasCustomValidity: false,
            validityEndpoints: [],
            global: true
        },
        "AWS Secret Key": {
            name: "AWS Secret Key",
            familyName: "AWS Access & Secret Keys",
            pattern: /"([A-Za-z0-9+/]{40})"|(?:[^A-Za-z0-9+/]|^)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)/g,
            entropy: 4.25,
            isValidityCustomizable: false,
            hasCustomValidity: false,
            validityEndpoints: [],
            global: true
        }
    } as Record<string, Pattern>;

    const mockOccurrence: AWSOccurrence = {
        accountId: "123456789876",
        arn: "arn:aws:iam::123456789876:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "cc01530b728e935478acaa8f03499c7c27d7ad7a8fc82ba51c5abb4d2d501214ea3df8b50c34a5cec235132869641d93e381215ef0e846424d024fda230adfec",
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

    const mockOccurrences: Set<Occurrence> = new Set([mockOccurrence]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "cc01530b728e935478acaa8f03499c7c27d7ad7a8fc82ba51c5abb4d2d501214ea3df8b50c34a5cec235132869641d93e381215ef0e846424d024fda230adfec",
            numOccurrences: 1,
            occurrences: mockOccurrences,
            validity: "valid",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        }
    ];

    beforeEach(() => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindings,
                patterns: mockPatterns,
            },
        });
        jest.clearAllMocks();
    });

    test('renders the table headers correctly', () => {
        render(<DetectorsTab />);
        const rows = screen.getAllByRole('row');
        expect(rows[0]).toHaveTextContent('Name');
        expect(rows[0]).toHaveTextContent('Entropy');
        expect(rows[0]).toHaveTextContent('Findings');
    });

    test('renders rows name correctly', () => {
        render(<DetectorsTab />);
        const rows = screen.getAllByRole('row');
        expect(rows[1]).toHaveTextContent('AWS Access Key');
        expect(rows[2]).toHaveTextContent('AWS Secret Key');
    });

    test('renders rows entropy correctly', () => {
        render(<DetectorsTab />);
        const rows = screen.getAllByRole('row');
        expect(rows[1]).toHaveTextContent('3');
        expect(rows[2]).toHaveTextContent('4.25');
    });

    test('renders rows correct number of findings', () => {
        render(<DetectorsTab />);
        const rows = screen.getAllByRole('row');
        expect(rows[1]).toHaveTextContent('1');
        expect(rows[2]).toHaveTextContent('1');
    });

    test('displays the view button for each pattern', () => {
        render(<DetectorsTab />);
        const viewButtons = screen.getAllByTitle('View Detector');
        expect(viewButtons).toHaveLength(2);
    });

    test('opens a new tab with correct URL when view button is clicked', () => {
        render(<DetectorsTab />);
        const viewButtons = screen.getAllByTitle('View Detector');
        fireEvent.click(viewButtons[0]);
        expect(chrome.runtime.getURL).toHaveBeenCalledWith('options.html');
        expect(chrome.tabs.create).toHaveBeenCalledWith({
            url: 'chrome-extension://extension-id/options.html?tab=detectors&familyname=AWS Access & Secret Keys',
        });
    });

    test('handles empty patterns object', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindings,
                patterns: {},
            },
        });
        render(<DetectorsTab />);
        const rows = screen.getAllByRole('row');
        expect(rows.length).toBe(1);
        expect(rows[0]).toHaveTextContent('Name');
        expect(rows[0]).toHaveTextContent('Entropy');
        expect(rows[0]).toHaveTextContent('Findings');
    });

    test('handles empty findings array', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: [],
                patterns: mockPatterns,
            },
        });

        render(<DetectorsTab />);
        const rows = screen.getAllByRole('row');
        expect(rows[1]).toHaveTextContent('0');
        expect(rows[2]).toHaveTextContent('0');
    });
});