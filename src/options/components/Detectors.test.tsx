import { render, screen, fireEvent } from '@testing-library/react';
import { Detectors } from './Detectors';
import { useAppContext } from '../../popup/AppContext';
import { Pattern } from '../../types/patterns.types';

jest.mock('lucide-react', () => ({
    ChevronDown: () => <div data-testid="chevron-down" />,
    ChevronUp: () => <div data-testid="chevron-up" />,
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
    
});
