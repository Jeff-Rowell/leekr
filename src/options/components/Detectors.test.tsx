import { fireEvent, render, screen } from '@testing-library/react';
import { useAppContext } from '../../popup/AppContext';
import { Pattern } from '../../types/patterns.types';
import { Detectors } from './Detectors';

jest.mock('lucide-react', () => ({
    ChevronDown: () => <div data-testid="chevron-down" />,
    ChevronUp: () => <div data-testid="chevron-up" />,
    ChevronLeft: () => <div data-testid="chevron-left" />,
    ChevronRight: () => <div data-testid="chevron-right" />,
    AlertTriangle: () => <div data-testid="alert-icon" />,
    Search: () => <div data-testid="search-icon" />,
}));


jest.mock('../../popup/AppContext', () => ({
    useAppContext: jest.fn(),
}));

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

// Create a larger dataset for pagination testing
const createLargePatternSet = () => {
    const patterns: Record<string, Pattern> = {};
    for (let i = 1; i <= 15; i++) {
        patterns[`Pattern ${i}`] = {
            name: `Pattern ${i}`,
            familyName: `Family ${Math.ceil(i / 3)}`,
            pattern: new RegExp(`pattern${i}`, 'g'),
            entropy: i * 0.5,
            isValidityCustomizable: false,
            hasCustomValidity: false,
            validityEndpoints: [],
            global: true
        };
    }
    return patterns;
};


describe('<Detectors />', () => {
    beforeEach(() => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                patterns: mockPatterns,
            },
        });
    });

    test('renders detector rows', () => {
        render(<Detectors familyname="" />);
        expect(screen.getByText(/AWS Access Key/i)).toBeInTheDocument();
        expect(screen.getByText(/AWS Secret Key/i)).toBeInTheDocument();
    });

    test('filters detectors by search input', () => {
        render(<Detectors familyname="" />);
        const searchInput = screen.getByPlaceholderText(/Search detectors/i);
        fireEvent.change(searchInput, { target: { value: 'aws' } });

        expect(screen.getByText(/AWS Access Key/i)).toBeInTheDocument();
        expect(screen.getByText(/AWS Secret Key/i)).toBeInTheDocument();
    });

    test('displays "No detectors" message if no match found', () => {
        render(<Detectors familyname="" />);
        const searchInput = screen.getByPlaceholderText(/Search detectors/i);
        fireEvent.change(searchInput, { target: { value: 'nonexistent' } });

        expect(screen.getByText(/No detectors match your search/i)).toBeInTheDocument();
    });

    test('sorts detectors by name ascending and descending', () => {
        render(<Detectors familyname="" />);
        const getNames = () => screen.getAllByRole('row').slice(1).map(row =>
            row.querySelector('td')?.textContent
        );

        let names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);
        
        const nameHeader = screen.getByRole('columnheader', { name: /^Name$/i });
        fireEvent.click(nameHeader);
        names = getNames();
        expect(names).toEqual(['AWS Secret Key', 'AWS Access Key']);

        fireEvent.click(nameHeader);
        names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);
    });

    test('sorts detectors by family name ascending and descending', () => {
        render(<Detectors familyname="" />);
        const getNames = () => screen.getAllByRole('row').slice(1).map(row =>
            row.querySelector('td')?.textContent
        );

        let names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);
        
        const nameHeader = screen.getByRole('columnheader', { name: /^Family Name$/i });
        fireEvent.click(nameHeader);
        names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);

        fireEvent.click(nameHeader);
        names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);
    });

    test('sorts detectors by pattern ascending and descending', () => {
        render(<Detectors familyname="" />);
        const getNames = () => screen.getAllByRole('row').slice(1).map(row =>
            row.querySelector('td')?.textContent
        );

        let names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);
        
        const nameHeader = screen.getByRole('columnheader', { name: /^Pattern$/i });
        fireEvent.click(nameHeader);
        names = getNames();
        expect(names).toEqual(['AWS Secret Key', 'AWS Access Key']);

        fireEvent.click(nameHeader);
        names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);
    });

    test('sorts detectors by entropy ascending and descending', () => {
        render(<Detectors familyname="" />);
        const getNames = () => screen.getAllByRole('row').slice(1).map(row =>
            row.querySelector('td')?.textContent
        );

        let names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);
        
        const nameHeader = screen.getByRole('columnheader', { name: /^Entropy$/i });
        fireEvent.click(nameHeader);
        fireEvent.click(nameHeader);
        names = getNames();
        expect(names).toEqual(['AWS Secret Key', 'AWS Access Key']);

        fireEvent.click(nameHeader);
        names = getNames();
        expect(names).toEqual(['AWS Access Key', 'AWS Secret Key']);
    });

    test('renders with an existing family name', () => {
        render(<Detectors familyname="AWS Access & Secret Keys" />);
        expect(screen.getByText(/AWS Access Key/i)).toBeInTheDocument();
        expect(screen.getByText(/AWS Secret Key/i)).toBeInTheDocument();
    });

    test('renders with a nonexistent family name', () => {
        render(<Detectors familyname="non existing" />);
        expect(screen.queryByText(/AWS Access Key/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/AWS Secret Key/i)).not.toBeInTheDocument();
    });

    test('renders pattern without global flag correctly', () => {
        const nonGlobalPattern = {
            name: "Non-global Pattern",
            familyName: "Test Family",
            pattern: /testpattern/,
            entropy: 1.5,
            isValidityCustomizable: false,
            hasCustomValidity: false,
            validityEndpoints: [],
            global: false
        };

        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                patterns: {
                    ...mockPatterns,
                    "Non-global Pattern": nonGlobalPattern
                },
            },
        });
        render(<Detectors familyname="" />);
        expect(screen.getByText(/Non-global Pattern/i)).toBeInTheDocument();

        const patternElements = screen.getAllByText('testpattern');
        expect(patternElements.length).toBeGreaterThan(0);
        patternElements.forEach(el => {
            expect(el.tagName.toLowerCase()).toBe('pre');
            expect(el.textContent).toBe('testpattern');
        });
    });

    describe('Pagination', () => {
        beforeEach(() => {
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    patterns: createLargePatternSet(),
                },
            });
        });

        test('displays pagination controls when there are more than 10 items', () => {
            render(<Detectors familyname="" />);
            
            expect(screen.getByText(/Showing 1-10 patterns from 5 detectors/)).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Previous page/ })).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Next page/ })).toBeInTheDocument();
            
            // Check for pagination page buttons using class selector
            const paginationContainer = document.querySelector('.pagination-pages');
            expect(paginationContainer).toBeInTheDocument();
            expect(paginationContainer?.querySelector('button')).toHaveTextContent('1');
        });

        test('does not display pagination controls when there are 10 or fewer items', () => {
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    patterns: mockPatterns,
                },
            });
            render(<Detectors familyname="" />);
            
            expect(screen.queryByText(/Showing/)).not.toBeInTheDocument();
            expect(screen.queryByRole('button', { name: /Previous page/ })).not.toBeInTheDocument();
            expect(screen.queryByRole('button', { name: /Next page/ })).not.toBeInTheDocument();
        });

        test('navigates to next page when next button is clicked', () => {
            render(<Detectors familyname="" />);
            
            // Debug: Let's see what's actually rendered
            // screen.debug();
            
            // Initially on page 1 - verify pagination is shown and check content
            expect(screen.getByText(/Showing 1-10 patterns from 5 detectors/)).toBeInTheDocument();
            
            // Count the number of table rows (excluding header)
            const tableRows = screen.getAllByRole('row');
            expect(tableRows).toHaveLength(11); // 1 header + 10 data rows
            
            // Verify first patterns are shown
            expect(screen.getByText('Pattern 1')).toBeInTheDocument();
            expect(screen.getByText('Pattern 2')).toBeInTheDocument();
            
            // Click next button
            const nextButton = screen.getByRole('button', { name: /Next page/ });
            fireEvent.click(nextButton);
            
            // Now on page 2 - should show remaining 5 patterns
            expect(screen.getByText(/Showing 11-15 patterns from 5 detectors/)).toBeInTheDocument();
            
            // Count rows again - should be 6 now (1 header + 5 data rows)
            const tableRowsPage2 = screen.getAllByRole('row');
            expect(tableRowsPage2).toHaveLength(6);
            
            // Check for patterns that should be on page 2 (alphabetical order: 1,10,11,12,13,14,15,2,3,4,5,6,7,8,9)
            // So page 2 should have Pattern 5, 6, 7, 8, 9
            expect(screen.getByText('Pattern 5')).toBeInTheDocument();
        });

        test('navigates to previous page when previous button is clicked', () => {
            render(<Detectors familyname="" />);
            
            // Navigate to page 2 first
            const nextButton = screen.getByRole('button', { name: /Next page/ });
            fireEvent.click(nextButton);
            expect(screen.getByText(/Showing 11-15 patterns from 5 detectors/)).toBeInTheDocument();
            
            // Click previous button
            const prevButton = screen.getByRole('button', { name: /Previous page/ });
            fireEvent.click(prevButton);
            
            // Back to page 1
            expect(screen.getByText(/Showing 1-10 patterns from 5 detectors/)).toBeInTheDocument();
            const tableRows = screen.getAllByRole('row');
            expect(tableRows).toHaveLength(11); // 1 header + 10 data rows
        });

        test('navigates to specific page when page number is clicked', () => {
            render(<Detectors familyname="" />);
            
            // Click on page 2 using class selector
            const paginationContainer = document.querySelector('.pagination-pages');
            const page2Button = paginationContainer?.querySelectorAll('button')[1];
            expect(page2Button).toHaveTextContent('2');
            fireEvent.click(page2Button!);
            
            expect(screen.getByText(/Showing 11-15 patterns from 5 detectors/)).toBeInTheDocument();
            const tableRows = screen.getAllByRole('row');
            expect(tableRows).toHaveLength(6); // 1 header + 5 data rows
        });

        test('disables previous button on first page', () => {
            render(<Detectors familyname="" />);
            
            const prevButton = screen.getByRole('button', { name: /Previous page/ });
            expect(prevButton).toBeDisabled();
        });

        test('disables next button on last page', () => {
            render(<Detectors familyname="" />);
            
            // Navigate to last page
            const nextButton = screen.getByRole('button', { name: /Next page/ });
            fireEvent.click(nextButton);
            
            expect(nextButton).toBeDisabled();
        });

        test('resets to page 1 when search filter changes', () => {
            render(<Detectors familyname="" />);
            
            // Navigate to page 2
            const nextButton = screen.getByRole('button', { name: /Next page/ });
            fireEvent.click(nextButton);
            expect(screen.getByText(/Showing 11-15 patterns from 5 detectors/)).toBeInTheDocument();
            
            // Apply search filter - this will match Pattern 1, Pattern 10, Pattern 11, etc.
            const searchInput = screen.getByPlaceholderText(/Search detectors/i);
            fireEvent.change(searchInput, { target: { value: 'Pattern 1' } });
            
            // Should be back on page 1 with filtered results (7 patterns: 1, 10, 11, 12, 13, 14, 15)
            // Since 7 < 10, no pagination should be shown
            expect(screen.queryByText(/Showing/)).not.toBeInTheDocument();
            
            // Check that we have the expected filtered patterns
            expect(screen.getByText('Pattern 1')).toBeInTheDocument();
            expect(screen.getByText('Pattern 10')).toBeInTheDocument();
        });

        test('highlights active page number', () => {
            render(<Detectors familyname="" />);
            
            const paginationContainer = document.querySelector('.pagination-pages');
            const page1Button = paginationContainer?.querySelectorAll('button')[0] as HTMLElement;
            const page2Button = paginationContainer?.querySelectorAll('button')[1] as HTMLElement;
            
            expect(page1Button).toHaveClass('active');
            
            fireEvent.click(page2Button);
            
            expect(page2Button).toHaveClass('active');
            expect(page1Button).not.toHaveClass('active');
        });
    });
    
});
