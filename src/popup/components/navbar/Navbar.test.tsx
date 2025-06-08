import '@testing-library/jest-dom';
import { fireEvent, render, screen } from '@testing-library/react';
import { useAppContext } from '../../AppContext';
import Navbar from './Navbar';


jest.mock('../../AppContext', () => ({
    useAppContext: jest.fn(),
}));

describe('Navbar Component', () => {
    const mockSetActiveTab = jest.fn();
    const defaultContextValue = {
        data: {
            activeTab: 'Findings',
            isExtensionEnabled: true,
        },
        actions: {
            setActiveTab: mockSetActiveTab,
        },
    };

    beforeEach(() => {
        jest.clearAllMocks();
        (useAppContext as jest.Mock).mockReturnValue(defaultContextValue);
    });

    test('renders all tabs correctly', () => {
        render(<Navbar />);
        expect(screen.getByText('Findings')).toBeInTheDocument();
        expect(screen.getByText('Detectors')).toBeInTheDocument();
        expect(screen.getByText('More')).toBeInTheDocument();
    });

    test('applies active class to the active tab', () => {
        render(<Navbar />);
        const activeButton = screen.getByText('Findings');
        expect(activeButton).toHaveClass('active');

        const inactiveButton1 = screen.getByText('Detectors');
        const inactiveButton2 = screen.getByText('More');
        expect(inactiveButton1).not.toHaveClass('active');
        expect(inactiveButton2).not.toHaveClass('active');
    });

    test('calls setActiveTab when clicking on a tab', () => {
        render(<Navbar />);

        const detectorsTab = screen.getByText('Detectors');
        fireEvent.click(detectorsTab);
        expect(mockSetActiveTab).toHaveBeenCalledWith('Detectors');
    });

    test('disables all tabs when isExtensionEnabled is false', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                activeTab: 'Findings',
                isExtensionEnabled: false,
            },
            actions: {
                setActiveTab: mockSetActiveTab,
            },
        });

        render(<Navbar />);
        const tabs = screen.getAllByRole('button');
        tabs.forEach(tab => {
            expect(tab).toBeDisabled();
        });
    });

    test('does not call setActiveTab when tabs are disabled', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                activeTab: 'Findings',
                isExtensionEnabled: false,
            },
            actions: {
                setActiveTab: mockSetActiveTab,
            },
        });

        render(<Navbar />);

        const detectorsTab = screen.getByText('Detectors');
        fireEvent.click(detectorsTab);
        expect(mockSetActiveTab).not.toHaveBeenCalled();
    });

    test('updates active tab when context changes', () => {
        const { rerender } = render(<Navbar />);
        const findingsTab = screen.getByText('Findings');
        expect(findingsTab).toHaveClass('active');

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                activeTab: 'Detectors',
                isExtensionEnabled: true,
            },
            actions: {
                setActiveTab: mockSetActiveTab,
            },
        });

        rerender(<Navbar />);

        const detectorsTab = screen.getByText('Detectors');
        expect(detectorsTab).toHaveClass('active');
        expect(findingsTab).not.toHaveClass('active');
    });
});