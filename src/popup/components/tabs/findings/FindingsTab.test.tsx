import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AWSOccurrence } from 'src/types/aws.types';
import { Finding, Occurrence } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../../../utils/helpers/common';
import { awsValidityHelper } from '../../../../utils/validators/aws_access_keys/awsValidityHelper';
import { useAppContext } from '../../../AppContext';
import FindingsTab from './FindingsTab';

jest.mock('../../../AppContext', () => ({
    useAppContext: jest.fn(),
}));

jest.mock('../../../../utils/validators/aws_access_keys/awsValidityHelper', () => ({
    awsValidityHelper: jest.fn(),
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

    beforeEach(() => {
        jest.clearAllMocks();
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindings,
            },
        });

        // Setup getBoundingClientRect mock for settings button
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

        // Set up scrollX and scrollY
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
    });

    test('applies correct validity color classes', () => {
        render(<FindingsTab />);

        const validElement = screen.getByText('valid').closest('.validity-status');
        const invalidElement = screen.getByText('invalid').closest('.validity-status');
        const unknownElement = screen.getByText('unknown').closest('.validity-status');
        const failedElement = screen.getByText('failed to check').closest('.validity-status');

        expect(validElement).toHaveClass('validity-valid');
        expect(invalidElement).toHaveClass('validity-invalid');
        expect(unknownElement).toHaveClass('validity-unknown');
        expect(failedElement).toHaveClass('validity-failed');
    });

    test('shows validity check icon for validated findings', () => {
        render(<FindingsTab />);
        const shieldIcons = screen.getAllByTestId('shield-check-icon');
        expect(shieldIcons.length).toBe(1);
    });

    test('opens settings menu when settings button is clicked', async () => {
        render(<FindingsTab />);

        const settingsButtons = screen.getAllByLabelText('Settings');
        expect(settingsButtons.length).toBe(4);
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
        const validityElements = screen.getAllByText(/valid/).filter(el =>
            el.closest('.validity-status')
        );
        fireEvent.mouseOver(validityElements[0]);
        const tooltips = document.querySelectorAll('.tooltip');
        let recheckButton: HTMLElement | null = null;
        tooltips.forEach(tooltip => {
            const button = tooltip.querySelector('[aria-label="Recheck validity"]');
            if (button) {
                recheckButton = button as HTMLElement;
            }
        });
        expect(recheckButton).not.toBeNull();

        if (recheckButton) {
            fireEvent.click(recheckButton);
            expect(awsValidityHelper).toHaveBeenCalledWith(mockFindings[0]);
        }
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