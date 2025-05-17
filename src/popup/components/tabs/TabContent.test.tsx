import { render, screen } from '@testing-library/react';
import TabContent from './TabContent';
import FindingsTab from './findings/FindingsTab';
import DetectorsTab from './detectors/DetectorsTab';
import MoreTab from './more/MoreTab';

jest.mock('./findings/FindingsTab', () => {
    return jest.fn(() => <div data-testid="findings-tab">Findings Content</div>);
});

jest.mock('./detectors/DetectorsTab', () => {
    return jest.fn(() => <div data-testid="detectors-tab">Detectors Content</div>);
});

jest.mock('./more/MoreTab', () => {
    return jest.fn(() => <div data-testid="more-tab">More Content</div>);
});

describe('TabContent', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders FindingsTab when activeTab is "Findings"', () => {
        render(<TabContent activeTab="Findings" />);
        expect(FindingsTab).toHaveBeenCalled();
        expect(screen.getByTestId('findings-tab')).toBeInTheDocument();
        expect(DetectorsTab).not.toHaveBeenCalled();
        expect(MoreTab).not.toHaveBeenCalled();
    });

    test('renders DetectorsTab when activeTab is "Detectors"', () => {
        render(<TabContent activeTab="Detectors" />);
        expect(DetectorsTab).toHaveBeenCalled();
        expect(screen.getByTestId('detectors-tab')).toBeInTheDocument();
        expect(FindingsTab).not.toHaveBeenCalled();
        expect(MoreTab).not.toHaveBeenCalled();
    });

    test('renders MoreTab when activeTab is "More"', () => {
        render(<TabContent activeTab="More" />);
        expect(MoreTab).toHaveBeenCalled();
        expect(screen.getByTestId('more-tab')).toBeInTheDocument();
        expect(FindingsTab).not.toHaveBeenCalled();
        expect(DetectorsTab).not.toHaveBeenCalled();
    });

    test('returns nothing when activeTab is not recognized', () => {
        const { container } = render(<TabContent activeTab="Unknown" />);
        expect(container.firstChild).toBeNull();
        expect(FindingsTab).not.toHaveBeenCalled();
        expect(DetectorsTab).not.toHaveBeenCalled();
        expect(MoreTab).not.toHaveBeenCalled();
    });
});