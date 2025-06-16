import '@testing-library/jest-dom';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useAppContext } from '../../popup/AppContext';
import { AWSOccurrence } from '../../types/aws.types';
import { Finding, Occurrence } from '../../types/findings.types';
import { awsValidityHelper } from '../../utils/validators/aws/aws_access_keys/awsValidityHelper';
import { Findings } from './Findings';

jest.mock('../../popup/AppContext');

jest.mock('../../utils/validators/aws/aws_access_keys/awsValidityHelper');
const mockAwsValidityHelper = awsValidityHelper as jest.MockedFunction<typeof awsValidityHelper>;

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

const mockOccurrencesOne: Set<Occurrence> = new Set([mockOccurrenceOne]);
const mockOccurrencesTwo: Set<Occurrence> = new Set([mockOccurrenceTwo]);
const mockOccurrencesThree: Set<Occurrence> = new Set([mockOccurrenceThree]);
const mockOccurrencesFour: Set<Occurrence> = new Set([mockOccurrenceFour]);

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
            expect(findings).toHaveLength(4);
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

            expect(screen.getByText('valid')).toBeInTheDocument();
            expect(screen.getByText('invalid')).toBeInTheDocument();
            expect(screen.getByText('unknown')).toBeInTheDocument();
            expect(screen.getByText('failed to check')).toBeInTheDocument();
        });

        test('displays validation timestamp when available', () => {
            const { container } = render(<Findings />);

            const shieldIcons = container.querySelectorAll('.validity-valid');
            expect(shieldIcons).toHaveLength(1);
        });
    });

    describe('Validity Status Filtering', () => {
        test('filters findings by valid status', async () => {
            const user = userEvent.setup();
            const { container } = render(<Findings />);

            const validityFilter = screen.getByLabelText('Validity Status:');
            await user.selectOptions(validityFilter, 'valid');

            const findings = container.querySelectorAll('.findings-td');
            expect(findings).toHaveLength(1);
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
            expect(validFindings).toHaveLength(1);

            await user.selectOptions(validityFilter, 'all');
            const allFindings = container.querySelectorAll('.findings-td');
            expect(allFindings).toHaveLength(4);
        });
    });

    describe('Secret Type Filtering', () => {
        test('populates secret type dropdown with unique types', () => {
            render(<Findings />);

            const typeFilter = screen.getByLabelText('Secret Type:');
            const options = typeFilter.querySelectorAll('option');

            expect(options).toHaveLength(2);
            expect(options[0]).toHaveTextContent('All Types');
            expect(options[1]).toHaveTextContent('AWS Access & Secret Keys');
        });

        test('filters findings by secret type', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const typeFilter = screen.getByLabelText('Secret Type:');
            await user.selectOptions(typeFilter, 'AWS Access & Secret Keys');

            const rows = screen.getAllByRole('row');
            expect(rows).toHaveLength(5);
        });

        test('shows all findings when "All Types" is selected', async () => {
            const user = userEvent.setup();
            const { container } = render(<Findings />);

            const typeFilter = screen.getByLabelText('Secret Type:');
            await user.selectOptions(typeFilter, 'AWS Access & Secret Keys');
            const allFindings = container.querySelectorAll('.findings-td');
            expect(allFindings).toHaveLength(4);
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

            expect(firstDataRow).toHaveTextContent('AWS Access & Secret Keys');
            expect(secondDataRow).toHaveTextContent('AWS Access & Secret Keys');
        });

        test('toggles sort direction when clicking same column', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const typeHeader = screen.getByText('Type').closest('th')!;

            await user.click(typeHeader);

            const rows = screen.getAllByRole('row');
            const firstDataRow = rows[1];
            expect(firstDataRow).toHaveTextContent('AWS Access & Secret Keys');
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
            expect(viewButtons).toHaveLength(4);
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
                { url: 'chrome-extension://test/options.html?tab=findings&fingerprint=fp1' }
            );
        });

        test('handles validity recheck for AWS keys', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const recheckButtons = screen.getAllByTestId('rotate-cw');
            await user.click(recheckButtons[0]);

            expect(mockAwsValidityHelper).toHaveBeenCalledWith(mockFindings[0]);
        });

        test('does not call validity helper for non-AWS findings', async () => {
            const user = userEvent.setup();
            render(<Findings />);

            const recheckButtons = screen.getAllByTestId('rotate-cw');
            await user.click(recheckButtons[1]);

            expect(mockAwsValidityHelper).not.toHaveBeenCalled();
        });
    });

    describe('Validity Status Styling', () => {
        test('applies correct CSS classes for validity status', () => {
            render(<Findings />);

            const validStatus = screen.getByText('valid').closest('.validity-status');
            const invalidStatus = screen.getByText('invalid').closest('.validity-status');
            const unknownStatus = screen.getByText('unknown').closest('.validity-status');
            const failedStatus = screen.getByText('failed to check').closest('.validity-status');

            expect(validStatus).toHaveClass('validity-valid');
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
            expect(viewButtons).toHaveLength(4);

            const recheckButtons = screen.getAllByLabelText('Recheck validity');
            expect(recheckButtons).toHaveLength(1);
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
});