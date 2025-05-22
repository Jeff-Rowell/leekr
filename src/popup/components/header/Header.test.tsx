import '@testing-library/jest-dom';
import Header from './Header';
import { Finding, Occurrence } from '../../../types/findings.types';
import { AWSOccurrence } from 'src/types/aws.types';
import { useAppContext } from '../../AppContext';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

jest.mock('../../AppContext', () => ({
    useAppContext: jest.fn(),
}));

jest.mock('../../../../public/icons/leekr_icon_128x128.png', () => 'test-leekr-icon.png');

jest.mock('../../../../public/assets/leekr-font.svg', () => {
    return {
        __esModule: true,
        default: () => <div data-testid="leekr-font">LeekrFont</div>,
    };
});

jest.mock('../modalheader/ModalHeader', () => {
    return jest.fn(({ title, onClose }) => (
        <div data-testid="modal-header">
            <h2>{title}</h2>
            <button onClick={onClose}>Close</button>
        </div>
    ));
});

jest.mock('lucide-react', () => ({
    Download: () => <div data-testid="download-icon">Download Icon</div>,
    Menu: () => <div data-testid="menu-icon">Menu Icon</div>,
}));

global.chrome = {
    runtime: {
        getURL: jest.fn((path) => `chrome-extension://extension-id/${path}`),
    },
    tabs: {
        create: jest.fn(),
    },
} as any;

URL.createObjectURL = jest.fn(() => 'blob:test-url');
URL.revokeObjectURL = jest.fn();

describe('Header Component', () => {
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

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockOccurrenceOne]);
    const mockOccurrencesTwo: Set<Occurrence> = new Set([mockOccurrenceOne, mockOccurrenceTwo]);

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
            fingerprint: "fp1",
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
    ]

    const mockFindingsEmpty: Finding[] = [];
    const mockFindingsSingle: Finding[] = [mockFindings[0]];

    const defaultContext = {
        data: {
            findings: mockFindings,
            isExtensionEnabled: true
        }
    };

    beforeEach(() => {
        jest.clearAllMocks();

        // Create a mock anchor element for downloads
        const mockAnchorElement = {
            href: '',
            download: '',
            click: jest.fn(),
            style: {},
            setAttribute: jest.fn(),
            getAttribute: jest.fn(),
        } as any;

        // Only mock document.createElement when it's called with 'a'
        const originalCreateElement = document.createElement;
        document.createElement = jest.fn().mockImplementation((tag: string) => {
            if (tag === 'a') {
                return mockAnchorElement;
            }
            // For all other elements, use the real createElement
            return originalCreateElement.call(document, tag);
        });

        // Mock only the specific methods we need for download functionality
        const originalAppendChild = document.body.appendChild;
        const originalRemoveChild = document.body.removeChild;

        document.body.appendChild = jest.fn().mockImplementation((node) => {
            // If it's our mock anchor, just return it
            if (node === mockAnchorElement) {
                return node;
            }
            // Otherwise use the real method
            return originalAppendChild.call(document.body, node);
        });

        document.body.removeChild = jest.fn().mockImplementation((node) => {
            // If it's our mock anchor, just return it
            if (node === mockAnchorElement) {
                return node;
            }
            // Otherwise use the real method
            return originalRemoveChild.call(document.body, node);
        });

        (useAppContext as jest.Mock).mockReturnValue(defaultContext);
    });

    test('renders header with logo and branding', () => {
        render(<Header />);

        expect(screen.getByAltText('Leekr')).toBeInTheDocument();
        expect(screen.getByTestId('leekr-font')).toBeInTheDocument();
    });

    test('displays correct count when multiple secrets are detected', () => {
        render(<Header />);

        expect(screen.getByText('2 Secrets Detected')).toBeInTheDocument();
    });

    test('displays correct count when one secret is detected', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindingsSingle,
                isExtensionEnabled: true
            }
        });

        render(<Header />);

        expect(screen.getByText('1 Secret Detected')).toBeInTheDocument();
    });

    test('does not display secret count when no secrets are detected', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindingsEmpty,
                isExtensionEnabled: true
            }
        });

        render(<Header />);

        expect(screen.queryByText(/Secret(s)? Detected/)).not.toBeInTheDocument();
    });

    test('displays download button when findings exist', () => {
        render(<Header />);

        expect(screen.getByTestId('download-icon')).toBeInTheDocument();
    });

    test('does not display download button when no findings exist', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindingsEmpty,
                isExtensionEnabled: true
            }
        });

        render(<Header />);

        expect(screen.queryByTestId('download-icon')).not.toBeInTheDocument();
    });

    test('shows download options when download button is clicked', () => {
        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        if (downloadButton) fireEvent.click(downloadButton);

        expect(screen.getByText('Findings Download')).toBeInTheDocument();
        expect(screen.getByText('CSV')).toBeInTheDocument();
        expect(screen.getByText('JSON')).toBeInTheDocument();
    });

    test('closes download options when close button is clicked', async () => {
        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        if (downloadButton) fireEvent.click(downloadButton);

        const closeButton = screen.getByText('Close');
        fireEvent.click(closeButton);

        await waitFor(() => {
            expect(screen.queryByText('Findings Download')).not.toBeInTheDocument();
        });
    });

    test('toggles redact secrets checkbox in download options', () => {
        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        if (downloadButton) fireEvent.click(downloadButton);

        const checkbox = screen.getByLabelText('Redact Secret Values');
        expect(checkbox).toBeChecked();

        fireEvent.click(checkbox);
        expect(checkbox).not.toBeChecked();

        fireEvent.click(checkbox);
        expect(checkbox).toBeChecked();
    });

    test('initiates CSV download when CSV button is clicked', () => {
        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        if (downloadButton) fireEvent.click(downloadButton);

        const checkbox = screen.getByLabelText('Redact Secret Values');
        expect(checkbox).toBeChecked();

        const csvButton = screen.getByText('CSV');
        fireEvent.click(csvButton);

        expect(document.createElement).toHaveBeenCalledWith('a');
        expect(URL.createObjectURL).toHaveBeenCalled();
        expect(document.body.appendChild).toHaveBeenCalled();
        expect(document.body.removeChild).toHaveBeenCalled();
        expect(URL.revokeObjectURL).toHaveBeenCalled();
    });

    test('initiates CSV download when CSV button is clicked without redacted secrets', () => {
        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        if (downloadButton) fireEvent.click(downloadButton);

        const checkbox = screen.getByLabelText('Redact Secret Values');
        expect(checkbox).toBeChecked();

        fireEvent.click(checkbox);
        expect(checkbox).not.toBeChecked();

        const jsonButton = screen.getByText('CSV');
        fireEvent.click(jsonButton);

        expect(document.createElement).toHaveBeenCalledWith('a');
        expect(URL.createObjectURL).toHaveBeenCalled();
        expect(document.body.appendChild).toHaveBeenCalled();
        expect(document.body.removeChild).toHaveBeenCalled();
        expect(URL.revokeObjectURL).toHaveBeenCalled();
    });

    test('initiates JSON download when JSON button is clicked with redacted secrets', () => {
        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        if (downloadButton) fireEvent.click(downloadButton);

        const checkbox = screen.getByLabelText('Redact Secret Values');
        expect(checkbox).toBeChecked();

        const jsonButton = screen.getByText('JSON');
        fireEvent.click(jsonButton);

        expect(document.createElement).toHaveBeenCalledWith('a');
        expect(URL.createObjectURL).toHaveBeenCalled();
        expect(document.body.appendChild).toHaveBeenCalled();
        expect(document.body.removeChild).toHaveBeenCalled();
        expect(URL.revokeObjectURL).toHaveBeenCalled();
    });

    test('initiates JSON download when JSON button is clicked without redacted secrets', () => {
        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        if (downloadButton) fireEvent.click(downloadButton);

        const checkbox = screen.getByLabelText('Redact Secret Values');
        expect(checkbox).toBeChecked();

        fireEvent.click(checkbox);
        expect(checkbox).not.toBeChecked();

        const jsonButton = screen.getByText('JSON');
        fireEvent.click(jsonButton);

        expect(document.createElement).toHaveBeenCalledWith('a');
        expect(URL.createObjectURL).toHaveBeenCalled();
        expect(document.body.appendChild).toHaveBeenCalled();
        expect(document.body.removeChild).toHaveBeenCalled();
        expect(URL.revokeObjectURL).toHaveBeenCalled();
    });

    test('shows config options when menu button is clicked', () => {
        render(<Header />);

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        if (menuButton) fireEvent.click(menuButton);

        expect(screen.getByText('Options')).toBeInTheDocument();
        expect(screen.getByText('All Findings')).toBeInTheDocument();
        expect(screen.getByText('Detectors')).toBeInTheDocument();
        expect(screen.getByText('Settings')).toBeInTheDocument();
        expect(screen.getByText('HotKeys')).toBeInTheDocument();
        expect(screen.getByText('About')).toBeInTheDocument();
    });

    test('closes config options when close button is clicked', async () => {
        render(<Header />);

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        if (menuButton) fireEvent.click(menuButton);

        const closeButton = screen.getAllByText('Close')[0];
        fireEvent.click(closeButton);

        await waitFor(() => {
            expect(screen.queryByText('Options')).not.toBeInTheDocument();
        });
    });

    test('closes config options when config options button is clicked', async () => {
        render(<Header />);

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        if (menuButton) fireEvent.click(menuButton);
        expect(screen.getByText('Options')).toBeInTheDocument();
        expect(screen.getByText('All Findings')).toBeInTheDocument();
        expect(screen.getByText('Detectors')).toBeInTheDocument();
        expect(screen.getByText('Settings')).toBeInTheDocument();
        expect(screen.getByText('HotKeys')).toBeInTheDocument();
        expect(screen.getByText('About')).toBeInTheDocument();
        if (menuButton) fireEvent.click(menuButton);

        await waitFor(() => {
            expect(screen.queryByText('Options')).not.toBeInTheDocument();
        });
    });

    test('navigates to options page with All Findings tab when clicked', () => {
        render(<Header />);

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        if (menuButton) fireEvent.click(menuButton);

        const allFindingsButton = screen.getByText('All Findings');
        fireEvent.click(allFindingsButton);

        expect(chrome.runtime.getURL).toHaveBeenCalledWith('options.html');
        expect(chrome.tabs.create).toHaveBeenCalledWith({
            url: 'chrome-extension://extension-id/options.html?tab=findings'
        });
    });

    test('navigates to options page with Detectors tab when clicked', () => {
        render(<Header />);

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        if (menuButton) fireEvent.click(menuButton);

        const detectorsButton = screen.getByText('Detectors');
        fireEvent.click(detectorsButton);

        expect(chrome.runtime.getURL).toHaveBeenCalledWith('options.html');
        expect(chrome.tabs.create).toHaveBeenCalledWith({
            url: 'chrome-extension://extension-id/options.html?tab=detectors'
        });
    });

    test('navigates to options page with Settings tab when clicked', () => {
        render(<Header />);

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        if (menuButton) fireEvent.click(menuButton);

        const settingsButton = screen.getByText('Settings');
        fireEvent.click(settingsButton);

        expect(chrome.runtime.getURL).toHaveBeenCalledWith('options.html');
        expect(chrome.tabs.create).toHaveBeenCalledWith({
            url: 'chrome-extension://extension-id/options.html?tab=settings'
        });
    });

    test('navigates to chrome extensions shortcut page when HotKeys is clicked', () => {
        render(<Header />);

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        if (menuButton) fireEvent.click(menuButton);

        const hotKeysButton = screen.getByText('HotKeys');
        fireEvent.click(hotKeysButton);

        expect(chrome.tabs.create).toHaveBeenCalledWith({
            url: 'chrome://extensions/shortcuts'
        });
    });

    test('navigates to options page with About tab when clicked', () => {
        render(<Header />);

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        if (menuButton) fireEvent.click(menuButton);

        const aboutButton = screen.getByText('About');
        fireEvent.click(aboutButton);

        expect(chrome.runtime.getURL).toHaveBeenCalledWith('options.html');
        expect(chrome.tabs.create).toHaveBeenCalledWith({
            url: 'chrome-extension://extension-id/options.html?tab=about'
        });
    });

    test('disables buttons when extension is not enabled', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                findings: mockFindings,
                isExtensionEnabled: false
            }
        });

        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        expect(downloadButton).toBeDisabled();

        const menuButton = screen.getByTestId('menu-icon').closest('button');
        expect(menuButton).toBeDisabled();
    });

    test('closes dropdowns when clicking outside', async () => {
        render(<Header />);

        const downloadButton = screen.getByTestId('download-icon').closest('button');
        if (downloadButton) fireEvent.click(downloadButton);

        expect(screen.getByText('Findings Download')).toBeInTheDocument();

        fireEvent.mouseDown(document.body);

        await waitFor(() => {
            expect(screen.queryByText('Findings Download')).not.toBeInTheDocument();
        });
    });
});