import { render, screen, fireEvent } from '@testing-library/react';
import Options from './Options';


jest.mock('../components/SettingsTab', () => ({
    SettingsTab: () => <div data-testid="settings-tab">Settings Tab Content</div>,
}));

jest.mock('../components/Occurrences', () => ({
    Occurrences: ({ filterFingerprint }: { filterFingerprint: string }) => (
        <div data-testid="occurrences-tab">
            Occurrences Tab Content - Filter: {filterFingerprint}
        </div>
    ),
}));

jest.mock('../components/Findings', () => ({
    Findings: () => <div data-testid="findings-tab">Findings Tab Content</div>,
}));

jest.mock('../components/Detectors', () => ({
    Detectors: ({ familyname }: { familyname: string }) => (
        <div data-testid="detectors-tab">
            Detectors Tab Content - Family: {familyname}
        </div>
    ),
}));

jest.mock('../components/About', () => ({
    AboutTab: () => <div data-testid="about-tab">About Tab Content</div>,
}));

jest.mock('../../../public/assets/leekr-font.svg', () => {
    return {
        __esModule: true,
        default: ({ className }: { className: string }) => (
            <div data-testid="leekr-font" className={className}>Leekr Font</div>
        ),
    };
});

jest.mock('lucide-react', () => ({
    Shield: ({ size }: { size: number }) => <div data-testid="shield-icon" data-size={size} />,
    Settings: ({ size }: { size: number }) => <div data-testid="settings-icon" data-size={size} />,
    Eye: ({ size }: { size: number }) => <div data-testid="eye-icon" data-size={size} />,
    Info: ({ size }: { size: number }) => <div data-testid="info-icon" data-size={size} />,
}));

const setSearchParams = (params: Record<string, string>) => {
    const searchParams = new URLSearchParams(params);
    Object.defineProperty(window, 'location', {
        value: {
            search: searchParams.toString(),
        },
        writable: true,
    });
};

describe('Options Component', () => {
    beforeEach(() => {
        Object.defineProperty(window, 'location', {
            value: {
                search: '',
            },
            writable: true,
        });
    });

    describe('Initial Rendering', () => {
        test('renders header with logo and Leekr font', () => {
            render(<Options />);

            expect(screen.getByAltText('Leekr Logo')).toBeInTheDocument();
            expect(screen.getByTestId('leekr-font')).toBeInTheDocument();
            expect(screen.getByTestId('leekr-font')).toHaveClass('h-10', 'leekr-svg');
        });

        test('renders navigation sidebar with all tabs', () => {
            render(<Options />);

            expect(screen.getByText('Findings')).toBeInTheDocument();
            expect(screen.getByText('Detectors')).toBeInTheDocument();
            expect(screen.getByText('Settings')).toBeInTheDocument();
            expect(screen.getByText('About')).toBeInTheDocument();

            expect(screen.getByTestId('eye-icon')).toHaveAttribute('data-size', '18');
            expect(screen.getByTestId('shield-icon')).toHaveAttribute('data-size', '18');
            expect(screen.getByTestId('settings-icon')).toHaveAttribute('data-size', '18');
            expect(screen.getByTestId('info-icon')).toHaveAttribute('data-size', '18');
        });

        test('renders findings tab by default', () => {
            render(<Options />);

            expect(screen.getByTestId('findings-tab')).toBeInTheDocument();
            expect(screen.getByText('Findings').closest('li')).toHaveClass('active');
        });
    });

    describe('URL Parameter Parsing', () => {
        test('sets active tab from URL parameter', () => {
            setSearchParams({ tab: 'settings' });
            render(<Options />);

            expect(screen.getByTestId('settings-tab')).toBeInTheDocument();
            expect(screen.getByText('Settings').closest('li')).toHaveClass('active');
        });

        test('renders occurrences when fingerprint parameter is provided', () => {
            setSearchParams({ tab: 'findings', fingerprint: 'test-fingerprint-123' });
            render(<Options />);

            expect(screen.getByTestId('occurrences-tab')).toBeInTheDocument();
            expect(screen.getByText('Occurrences Tab Content - Filter: test-fingerprint-123')).toBeInTheDocument();
        });

        test('renders detectors with familyname parameter', () => {
            setSearchParams({ tab: 'detectors', familyname: 'test-family' });
            render(<Options />);

            expect(screen.getByTestId('detectors-tab')).toBeInTheDocument();
            expect(screen.getByText('Detectors Tab Content - Family: test-family')).toBeInTheDocument();
        });

        test('handles multiple URL parameters correctly', () => {
            setSearchParams({
                tab: 'findings',
                fingerprint: 'fp-123',
                familyname: 'family-456'
            });
            render(<Options />);

            expect(screen.getByTestId('occurrences-tab')).toBeInTheDocument();
            expect(screen.getByText('Occurrences Tab Content - Filter: fp-123')).toBeInTheDocument();
        });
    });

    describe('Tab Navigation', () => {
        test('switches to detectors tab when clicked', () => {
            render(<Options />);

            fireEvent.click(screen.getByText('Detectors'));

            expect(screen.getByTestId('detectors-tab')).toBeInTheDocument();
            expect(screen.getByText('Detectors').closest('li')).toHaveClass('active');
            expect(screen.getByText('Findings').closest('li')).not.toHaveClass('active');
        });

        test('switches to settings tab when clicked', () => {
            render(<Options />);

            fireEvent.click(screen.getByText('Settings'));

            expect(screen.getByTestId('settings-tab')).toBeInTheDocument();
            expect(screen.getByText('Settings').closest('li')).toHaveClass('active');
        });

        test('switches to about tab when clicked', () => {
            render(<Options />);

            fireEvent.click(screen.getByText('About'));

            expect(screen.getByTestId('about-tab')).toBeInTheDocument();
            expect(screen.getByText('About').closest('li')).toHaveClass('active');
        });

        test('clears fingerprint filter when clicking Findings tab', () => {
            setSearchParams({ tab: 'findings', fingerprint: 'test-fp' });
            render(<Options />);
            expect(screen.getByTestId('occurrences-tab')).toBeInTheDocument();

            fireEvent.click(screen.getByText('Findings'));
            expect(screen.getByTestId('findings-tab')).toBeInTheDocument();
            expect(screen.queryByTestId('occurrences-tab')).not.toBeInTheDocument();
        });
    });

    describe('Conditional Rendering Logic', () => {
        test('renders findings when no fingerprint filter', () => {
            setSearchParams({ tab: 'findings' });
            render(<Options />);

            expect(screen.getByTestId('findings-tab')).toBeInTheDocument();
        });

        test('renders occurrences when fingerprint filter is present', () => {
            setSearchParams({ tab: 'findings', fingerprint: 'test-fp' });
            render(<Options />);

            expect(screen.getByTestId('occurrences-tab')).toBeInTheDocument();
            expect(screen.queryByTestId('findings-tab')).not.toBeInTheDocument();
        });

        test('renders detectors without familyname as empty string', () => {
            setSearchParams({ tab: 'detectors' });
            render(<Options />);

            expect(screen.getByTestId('detectors-tab')).toBeInTheDocument();
            expect(screen.getByText('Detectors Tab Content - Family:')).toBeInTheDocument();
        });

        test('renders detectors with familyname parameter', () => {
            setSearchParams({ tab: 'detectors', familyname: 'aws' });
            render(<Options />);

            expect(screen.getByTestId('detectors-tab')).toBeInTheDocument();
            expect(screen.getByText('Detectors Tab Content - Family: aws')).toBeInTheDocument();
        });

        test('renders findings for unknown tab parameter', () => {
            setSearchParams({ tab: 'unknown-tab' });
            render(<Options />);

            expect(screen.getByTestId('findings-tab')).toBeInTheDocument();
        });
    });

    describe('Tab State Management', () => {
        test('maintains active state correctly when switching tabs', () => {
            render(<Options />);


            expect(screen.getByText('Findings').closest('li')).toHaveClass('active');
            expect(screen.getByText('Settings').closest('li')).not.toHaveClass('active');

            fireEvent.click(screen.getByText('Settings'));
            expect(screen.getByText('Settings').closest('li')).toHaveClass('active');
            expect(screen.getByText('Findings').closest('li')).not.toHaveClass('active');

            fireEvent.click(screen.getByText('Findings'));
            expect(screen.getByText('Findings').closest('li')).toHaveClass('active');
            expect(screen.getByText('Settings').closest('li')).not.toHaveClass('active');
        });

        test('preserves familyname filter when switching to detectors tab', () => {
            setSearchParams({ familyname: 'test-family' });
            render(<Options />);

            fireEvent.click(screen.getByText('Detectors'));

            expect(screen.getByTestId('detectors-tab')).toBeInTheDocument();
            expect(screen.getByText('Detectors Tab Content - Family: test-family')).toBeInTheDocument();
        });
    });

    describe('Edge Cases', () => {
        test('handles empty URL parameters gracefully', () => {
            setSearchParams({ tab: '', fingerprint: '', familyname: '' });
            render(<Options />);

            expect(screen.getByTestId('findings-tab')).toBeInTheDocument();
            expect(screen.getByText('Findings').closest('li')).toHaveClass('active');
        });

        test('handles malformed URL parameters', () => {
            Object.defineProperty(window, 'location', {
                value: {
                    search: '?tab=findings&fingerprint&familyname=',
                },
                writable: true,
            });
            render(<Options />);

            expect(screen.getByTestId('findings-tab')).toBeInTheDocument();
        });
    });
});