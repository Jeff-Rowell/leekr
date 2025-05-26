import { render, screen, fireEvent } from '@testing-library/react';
import { SettingsTab } from './SettingsTab';
import { useAppContext } from '../../popup/AppContext';

jest.mock('../../popup/AppContext');

const mockSetSuffixes = jest.fn();
const mockSetCustomSuffixesEnabled = jest.fn();

const defaultSuffixes = [
    { id: '1', value: '.js', isDefault: true },
    { id: '2', value: '.ts', isDefault: true },
    { id: '3', value: '.jsx', isDefault: false },
];

const renderWithMockContext = (
    customSuffixesEnabled = true,
    suffixes = defaultSuffixes
) => {
    (useAppContext as jest.Mock).mockReturnValue({
        data: { suffixes, customSuffixesEnabled },
        actions: {
            setSuffixes: mockSetSuffixes,
            setCustomSuffixesEnabled: mockSetCustomSuffixesEnabled,
        },
    });

    render(<SettingsTab />);
};

describe('SettingsTab Component', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders toggle and suffix list when custom suffixes are enabled', () => {
        renderWithMockContext();

        expect(screen.getByText(/Enable Custom Scan Suffixes/i)).toBeInTheDocument();
        expect(screen.getByText('.js')).toBeInTheDocument();
        expect(screen.getByText('.ts')).toBeInTheDocument();
        expect(screen.getByText('.jsx')).toBeInTheDocument();
    });

    test('clicking toggle switch calls setCustomSuffixesEnabled', () => {
        renderWithMockContext(true);
        const toggle = screen.getByRole('checkbox');
        fireEvent.click(toggle.parentElement!);

        expect(mockSetCustomSuffixesEnabled).toHaveBeenCalledWith(false);
    });

    test('adds a new valid suffix', () => {
        renderWithMockContext(true);

        fireEvent.change(screen.getByPlaceholderText(/add new suffix/i), {
            target: { value: 'tsx' },
        });
        fireEvent.click(screen.getByText('Add'));

        expect(mockSetSuffixes).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({ value: '.tsx' }),
            ])
        );
    });

    test('shows error when adding duplicate suffix', () => {
        renderWithMockContext(true);

        fireEvent.change(screen.getByPlaceholderText(/add new suffix/i), {
            target: { value: '.js' },
        });
        fireEvent.click(screen.getByText('Add'));

        expect(
            screen.getByText('This suffix already exists')
        ).toBeInTheDocument();
        expect(mockSetSuffixes).not.toHaveBeenCalled();
    });

    test('shows error when adding empty suffix', () => {
        renderWithMockContext(true);

        fireEvent.click(screen.getByText('Add'));

        expect(screen.getByText('Please enter a suffix')).toBeInTheDocument();
        expect(mockSetSuffixes).not.toHaveBeenCalled();
    });

    test('deletes a non-default suffix', () => {
        renderWithMockContext(true);

        fireEvent.click(screen.getAllByTitle('Delete suffix')[0]);

        expect(mockSetSuffixes).toHaveBeenCalledWith(
            expect.not.arrayContaining([
                expect.objectContaining({ id: '3' }),
            ])
        );
    });

    test('resets to default suffixes', () => {
        renderWithMockContext(true);

        fireEvent.click(screen.getByText('Reset to Defaults'));

        expect(mockSetSuffixes).toHaveBeenCalledWith(
            expect.arrayContaining([
                expect.objectContaining({ isDefault: true }),
            ])
        );
    });

    test('does not render suffix list or form when customSuffixesEnabled is false', () => {
        renderWithMockContext(false);

        expect(
            screen.queryByPlaceholderText(/add new suffix/i)
        ).not.toBeInTheDocument();
        expect(screen.queryByText('.js')).not.toBeInTheDocument();
        expect(screen.queryByText('.jsx')).not.toBeInTheDocument();
    });

    test('clicking toggle when customSuffixesEnabled is false enables it', () => {
        renderWithMockContext(false);
        const toggle = screen.getByRole('checkbox');

        fireEvent.click(toggle.parentElement!);
        fireEvent.click(toggle);
        expect(mockSetCustomSuffixesEnabled).toHaveBeenCalledWith(true);
    });
});
