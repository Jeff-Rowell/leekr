import '@testing-library/jest-dom';
import { fireEvent, render, screen } from '@testing-library/react';
import ModalHeader from './ModalHeader';


jest.mock('lucide-react', () => ({
    X: () => <div data-testid="x-icon">X Icon</div>
}));

describe('ModalHeader Component', () => {
    const mockOnClose = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders with the provided title', () => {
        render(<ModalHeader title="Test Modal" onClose={mockOnClose} />);
        expect(screen.getByText('Test Modal')).toBeInTheDocument();
    });

    test('renders without title when not provided', () => {
        render(<ModalHeader onClose={mockOnClose} />);

        const headingElement = screen.getByRole('heading');
        expect(headingElement).toBeInTheDocument();
        expect(headingElement.textContent).toBe('');
    });

    test('renders close button with X icon', () => {
        render(<ModalHeader title="Test Modal" onClose={mockOnClose} />);
        expect(screen.getByTestId('x-icon')).toBeInTheDocument();
    });

    test('calls onClose when close button is clicked', () => {
        render(<ModalHeader title="Test Modal" onClose={mockOnClose} />);

        const closeButton = screen.getByRole('button', { name: /close modal/i });
        fireEvent.click(closeButton);

        expect(mockOnClose).toHaveBeenCalledTimes(1);
    });

    test('close button has proper accessibility attributes', () => {
        render(<ModalHeader title="Test Modal" onClose={mockOnClose} />);

        const closeButton = screen.getByRole('button');

        expect(closeButton).toHaveAttribute('aria-label', 'Close modal');
    });

    test('applies correct CSS classes to elements', () => {
        render(<ModalHeader title="Test Modal" onClose={mockOnClose} />);

        const headerContainer = screen.getByText('Test Modal').parentElement;
        expect(headerContainer).toHaveClass('modal-header');

        const closeButton = screen.getByRole('button');
        expect(closeButton).toHaveClass('transition-colors');
        expect(closeButton).toHaveClass('duration-200');
    });

    test('renders heading as h1 element', () => {
        render(<ModalHeader title="Test Modal" onClose={mockOnClose} />);

        const heading = screen.getByRole('heading', { level: 1 });
        expect(heading).toBeInTheDocument();
        expect(heading.textContent).toBe('Test Modal');
    });
});