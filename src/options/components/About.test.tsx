import '@testing-library/jest-dom';
import { render, screen, waitFor } from '@testing-library/react';
import { AboutTab } from './About';

const mockChromeRuntime = {
    getManifest: jest.fn()
};

Object.defineProperty(global, 'chrome', {
    value: {
        runtime: mockChromeRuntime
    },
    writable: true
});

const mockConsoleError = jest.spyOn(console, 'error').mockImplementation(() => { });

describe('AboutTab Component', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockChromeRuntime.getManifest.mockReturnValue({ version: '2.1.0' });
    });

    afterAll(() => {
        mockConsoleError.mockRestore();
    });

    describe('Rendering', () => {
        test('renders the component without crashing', () => {
            render(<AboutTab />);
            expect(screen.getByText('About')).toBeInTheDocument();
        });

        test('displays the logo image with correct attributes', () => {
            render(<AboutTab />);
            const logo = screen.getByAltText('Leekr Logo');
            expect(logo).toBeInTheDocument();
            expect(logo).toHaveAttribute('src', 'icons/leekr.png');
            expect(logo).toHaveClass('about-logo');
        });

        test('displays the main description', () => {
            const { container } = render(<AboutTab />);

            const featureItems = container.querySelectorAll('.about-content-header-text');
            expect(featureItems).toHaveLength(1)
            expect(featureItems[0].textContent).toContain("Leekr passively identifies secrets exposed in client-side JavaScript while you browse the web.")
        });

        test('renders all section headings', () => {
            render(<AboutTab />);
            expect(screen.getByText('About')).toBeInTheDocument();
            expect(screen.getByText('Key Features')).toBeInTheDocument();
            expect(screen.getByText('Open Source')).toBeInTheDocument();
        });

        test('displays the about section description', () => {
            render(<AboutTab />);
            expect(screen.getByText(/Leekr is an/)).toBeInTheDocument();
            expect(screen.getByText(/open-source/)).toBeInTheDocument();
            expect(screen.getByText(/MIT-licensed/)).toBeInTheDocument();
        });
    });

    describe('Version Display', () => {
        test('displays default version initially', () => {
            const { container } = render(<AboutTab />);

            const featureItems = container.querySelectorAll('.version-badge');
            expect(featureItems).toHaveLength(1)
            expect(featureItems[0].textContent).toContain("v2.1.0")
        });

        test('updates version from chrome manifest when available', async () => {
            mockChromeRuntime.getManifest.mockReturnValue({ version: '2.1.0' });

            render(<AboutTab />);

            await waitFor(() => {
                expect(screen.getByText('v2.1.0')).toBeInTheDocument();
            });

            expect(mockChromeRuntime.getManifest).toHaveBeenCalledTimes(1);
        });

        test('handles chrome API errors gracefully', async () => {
            mockChromeRuntime.getManifest.mockImplementation(() => {
                throw new Error('Chrome API error');
            });

            render(<AboutTab />);

            await waitFor(() => {
                expect(mockConsoleError).toHaveBeenCalledWith('Error fetching extension version:', expect.any(Error));
            });

            expect(screen.getByText('v1.0.0')).toBeInTheDocument();
        });
    });

    describe('Feature List', () => {
        test('renders all feature items', () => {
            render(<AboutTab />);

            const features = [
                'Passive Detection',
                'Multiple Secret Types',
                'Customizable',
                'Validity Checks',
                'Configuration Sharing',
                'Source Code Attribution'
            ];

            features.forEach(feature => {
                expect(screen.getByText(feature)).toBeInTheDocument();
            });
        });

        test('displays feature descriptions', () => {
            render(<AboutTab />);

            expect(screen.getByText('Automatically scans JavaScript files while you browse')).toBeInTheDocument();
            expect(screen.getByText('Identifies API keys, tokens, and cloud credentials')).toBeInTheDocument();
            expect(screen.getByText('Customize file suffixes and Leekr will listen for those files')).toBeInTheDocument();
            expect(screen.getByText('Verifies and only notifies if discovered secrets are valid')).toBeInTheDocument();
            expect(screen.getByText('Share your configuration with others or accross devices.')).toBeInTheDocument();
            expect(screen.getByText('Identifies the exact lines of code that introduced the exposure.')).toBeInTheDocument();
        });

        test('displays feature icons', () => {
            render(<AboutTab />);

            const icons = ['🔍', '🔑', '⚙️', '✅', '🔄', '📃'];
            icons.forEach(icon => {
                expect(screen.getByText(icon)).toBeInTheDocument();
            });
        });
    });

    describe('Footer Links', () => {
        test('renders GitHub repository link with correct attributes', () => {
            render(<AboutTab />);

            const githubLink = screen.getByRole('link', { name: /GitHub Repository/i });
            expect(githubLink).toBeInTheDocument();
            expect(githubLink).toHaveAttribute('href', 'https://github.com/Jeff-Rowell/leekr');
            expect(githubLink).toHaveAttribute('target', '_blank');
            expect(githubLink).toHaveAttribute('rel', 'noopener noreferrer');
        });

        test('renders Privacy Policy link with correct attributes', () => {
            render(<AboutTab />);

            const privacyLink = screen.getByRole('link', { name: /Privacy Policy/i });
            expect(privacyLink).toBeInTheDocument();
            expect(privacyLink).toHaveAttribute('href', 'https://leekr-site.github.io/index/privacy');
            expect(privacyLink).toHaveAttribute('target', '_blank');
            expect(privacyLink).toHaveAttribute('rel', 'noopener noreferrer');
        });

        test('displays current year in copyright', () => {
            render(<AboutTab />);

            const currentYear = new Date().getFullYear();
            expect(screen.getByText(`© ${currentYear} Leekr`)).toBeInTheDocument();
        });
    });

    describe('CSS Classes', () => {
        test('applies correct CSS classes to main elements', () => {
            const { container } = render(<AboutTab />);

            expect(container.querySelector('.tab-content')).toBeInTheDocument();
            expect(container.querySelector('.about-section')).toBeInTheDocument();
            expect(container.querySelector('.about-content')).toBeInTheDocument();
            expect(container.querySelector('.about-header')).toBeInTheDocument();
            expect(container.querySelector('.version-badge')).toBeInTheDocument();
            expect(container.querySelector('.feature-list')).toBeInTheDocument();
            expect(container.querySelector('.about-footer')).toBeInTheDocument();
        });

        test('applies correct classes to feature items', () => {
            const { container } = render(<AboutTab />);

            const featureItems = container.querySelectorAll('.feature-item');
            expect(featureItems).toHaveLength(6);

            featureItems.forEach(item => {
                expect(item.querySelector('.feature-icon')).toBeInTheDocument();
                expect(item.querySelector('.feature-text')).toBeInTheDocument();
            });
        });
    });

    describe('Accessibility', () => {
        test('has proper heading hierarchy', () => {
            render(<AboutTab />);

            const h3Headings = screen.getAllByRole('heading', { level: 3 });
            expect(h3Headings).toHaveLength(3);
            expect(h3Headings[0]).toHaveTextContent('About');
            expect(h3Headings[1]).toHaveTextContent('Key Features');
            expect(h3Headings[2]).toHaveTextContent('Open Source');
        });

        test('has accessible external links', () => {
            render(<AboutTab />);

            const externalLinks = screen.getAllByRole('link');
            externalLinks.forEach(link => {
                expect(link).toHaveAttribute('target', '_blank');
                expect(link).toHaveAttribute('rel', 'noopener noreferrer');
            });
        });

        test('has proper alt text for images', () => {
            render(<AboutTab />);

            const logo = screen.getByAltText('Leekr Logo');
            expect(logo).toBeInTheDocument();
        });
    });

    describe('Edge Cases', () => {
        test('handles undefined chrome runtime gracefully', async () => {
            const originalChrome = (global as any).chrome;
            (global as any).chrome = { runtime: undefined };

            render(<AboutTab />);

            await new Promise(resolve => setTimeout(resolve, 0));

            expect(screen.getByText('v1.0.0')).toBeInTheDocument();

            (global as any).chrome = originalChrome;
        });

        test('handles chrome runtime without getManifest gracefully', async () => {
            const originalChrome = (global as any).chrome;
            (global as any).chrome = { runtime: {} };

            render(<AboutTab />);

            await new Promise(resolve => setTimeout(resolve, 0));

            expect(screen.getByText('v1.0.0')).toBeInTheDocument();

            (global as any).chrome = originalChrome;
        });
    });
});