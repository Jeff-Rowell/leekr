import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import Layout from './Layout';
import { useAppContext } from '../AppContext';

jest.mock('../AppContext', () => ({
    useAppContext: jest.fn()
}));

jest.mock('../components/header/Header', () => () => <div data-testid="header-component">Header</div>);
jest.mock('../components/navbar/Navbar', () => () => <div data-testid="navbar-component">Navbar</div>);
jest.mock('../components/tabs/TabContent', () => ({ activeTab }: { activeTab: string }) => (
    <div data-testid="tab-content-component" data-active-tab={activeTab}>
        TabContent for {activeTab}
    </div>
));

describe('Layout Component', () => {
    const setupMockContext = (isEnabled: boolean, activeTab: string) => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                isExtensionEnabled: isEnabled,
                activeTab: activeTab
            }
        });
    };
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders with enabled class when extension is enabled', () => {
        setupMockContext(true, 'Findings');
        const { container } = render(<Layout />);
        expect(container.firstChild).toHaveClass('content');
        expect(container.firstChild).not.toHaveClass('content-disabled');
        expect(screen.getByTestId('header-component')).toBeInTheDocument();
        expect(screen.getByTestId('navbar-component')).toBeInTheDocument();
        expect(screen.getByTestId('tab-content-component')).toBeInTheDocument();
    });

    test('renders with disabled class when extension is disabled', () => {
        setupMockContext(false, 'Findings');
        const { container } = render(<Layout />);
        expect(container.firstChild).toHaveClass('content-disabled');
        expect(container.firstChild).not.toHaveClass('content');
        expect(screen.getByTestId('header-component')).toBeInTheDocument();
        expect(screen.getByTestId('navbar-component')).toBeInTheDocument();
        expect(screen.getByTestId('tab-content-component')).toBeInTheDocument();
    });

    test('passes the Findings tab to TabContent component', () => {
        setupMockContext(true, 'Findings');
        render(<Layout />);
        const tabContent = screen.getByTestId('tab-content-component');
        expect(tabContent).toHaveAttribute('data-active-tab', 'Findings');
        expect(tabContent).toHaveTextContent('TabContent for Findings');
    });

    test('passes the Detectors tab to TabContent component', () => {
        setupMockContext(true, 'Detectors');
        render(<Layout />);
        const tabContent = screen.getByTestId('tab-content-component');
        expect(tabContent).toHaveAttribute('data-active-tab', 'Detectors');
        expect(tabContent).toHaveTextContent('TabContent for Detectors');
    });

    test('passes the More tab to TabContent component', () => {
        setupMockContext(true, 'More');
        render(<Layout />);
        const tabContent = screen.getByTestId('tab-content-component');
        expect(tabContent).toHaveAttribute('data-active-tab', 'More');
        expect(tabContent).toHaveTextContent('TabContent for More');
    });

    test('renders all child components in the correct order', () => {
        setupMockContext(true, 'Findings');
        const { container } = render(<Layout />);
        const contentDiv = container.firstChild as HTMLElement;
        const children = Array.from(contentDiv.children);
        expect(children[0]).toHaveAttribute('data-testid', 'header-component');
        expect(children[1]).toHaveAttribute('data-testid', 'navbar-component');
        expect(children[2]).toHaveAttribute('data-testid', 'tab-content-component');
    });
});