
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { useAppContext } from '../../../AppContext';
import MoreTab from './MoreTab';

jest.mock('../../../AppContext', () => ({
    useAppContext: jest.fn(),
}));

const mockConfirm = jest.fn();
window.confirm = mockConfirm;

describe('MoreTab Component', () => {

    const mockClearAllFindings = jest.fn();
    const mockToggleExtension = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('when extension is enabled', () => {
        beforeEach(() => {
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    isExtensionEnabled: true,
                },
                actions: {
                    clearAllFindings: mockClearAllFindings,
                    toggleExtension: mockToggleExtension,
                },
            });
        });

        test('renders correctly with enabled state', () => {
            render(<MoreTab />);

            expect(screen.getByText('Disable Extension')).toBeInTheDocument();
            expect(screen.getByText('Turn Off')).toBeInTheDocument();
            expect(screen.getByText('Delete All Findings')).toBeInTheDocument();

            const toggleButton = screen.getByText('Turn Off').closest('.toggle-button');
            expect(toggleButton).toHaveClass('disabled');
            expect(toggleButton).not.toHaveClass('enabled');
        });

        test('calls toggleExtension with false when toggle button is clicked', () => {
            render(<MoreTab />);
            const powerIcon = screen.getByText('Turn Off');
            fireEvent.click(powerIcon);
            expect(mockToggleExtension).toHaveBeenCalledWith(false);
        });

        test('shows confirmation dialog and clears findings when confirmed', () => {
            mockConfirm.mockReturnValueOnce(true);
            render(<MoreTab />);
            const trashIcon = screen.getByText('Delete All Findings')
                .closest('.more-tab-card')
                ?.querySelector('.more-tab-card-icon svg');

            if (trashIcon) {
                fireEvent.click(trashIcon);
            } else {
                fail('Trash icon not found');
            }

            expect(mockConfirm).toHaveBeenCalledWith(
                'Are you sure you want to clear all findings? This action cannot be undone.'
            );
            expect(mockClearAllFindings).toHaveBeenCalled();
        });

        test('does not clear findings when confirmation is canceled', () => {
            mockConfirm.mockReturnValueOnce(false);
            render(<MoreTab />);
            const trashIcon = screen.getByText('Delete All Findings')
                .closest('.more-tab-card')
                ?.querySelector('.more-tab-card-icon svg');

            if (trashIcon) {
                fireEvent.click(trashIcon);
            } else {
                fail('Trash icon not found');
            }
            expect(mockConfirm).toHaveBeenCalled();
            expect(mockClearAllFindings).not.toHaveBeenCalled();
        });
    });

    describe('when extension is disabled', () => {
        beforeEach(() => {
            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    isExtensionEnabled: false,
                },
                actions: {
                    clearAllFindings: mockClearAllFindings,
                    toggleExtension: mockToggleExtension,
                },
            });
        });

        test('renders correctly with disabled state', () => {
            render(<MoreTab />);
            expect(screen.getByText('Enable Extension')).toBeInTheDocument();
            expect(screen.getByText('Turn On')).toBeInTheDocument();

            const toggleButton = screen.getByText('Turn On').closest('.toggle-button');
            expect(toggleButton).toHaveClass('enabled');
            expect(toggleButton).not.toHaveClass('disabled');
        });

        test('calls toggleExtension with true when toggle button is clicked', () => {
            render(<MoreTab />);
            const powerIcon = screen.getByText('Turn On');
            fireEvent.click(powerIcon);
            expect(mockToggleExtension).toHaveBeenCalledWith(true);
        });

        test('clicking trash icon does not show confirmation when extension is disabled', () => {
            render(<MoreTab />);

            const trashIcon = screen.getByText('Delete All Findings')
                .closest('.more-tab-card')
                ?.querySelector('.more-tab-card-icon svg');
            if (trashIcon) {
                fireEvent.click(trashIcon);
            } else {
                fail('Trash icon not found');
            }
            expect(mockConfirm).not.toHaveBeenCalled();
            expect(mockClearAllFindings).not.toHaveBeenCalled();
        });
    });

    describe('External DOM manipulation tests', () => {
        let externalElement: HTMLElement;

        beforeEach(() => {
            externalElement = document.createElement('div');
            externalElement.id = 'external-element';
            document.body.appendChild(externalElement);

            (useAppContext as jest.Mock).mockReturnValue({
                data: {
                    isExtensionEnabled: true,
                },
                actions: {
                    clearAllFindings: mockClearAllFindings,
                    toggleExtension: jest.fn().mockImplementation((value) => {
                        if (!value) {
                            document.getElementById('external-element')?.classList.add('extension-disabled');
                            document.getElementById('external-element')?.classList.remove('extension-enabled');
                        } else {
                            document.getElementById('external-element')?.classList.add('extension-enabled');
                            document.getElementById('external-element')?.classList.remove('extension-disabled');
                        }
                    }),
                },
            });
        });

        afterEach(() => {
            document.body.removeChild(externalElement);
        });

        test('toggles class on external element when extension is toggled', () => {
            render(<MoreTab />);

            expect(document.getElementById('external-element')).not.toHaveClass('extension-disabled');

            const toggleButton = screen.getByText('Turn Off');
            act(() => {
                fireEvent.click(toggleButton);
            });

            expect(document.getElementById('external-element')).toHaveClass('extension-disabled');
            expect(document.getElementById('external-element')).not.toHaveClass('extension-enabled');
        });

        test('uses a custom DOM selector to find and check external elements', () => {
            const element1 = document.createElement('div');
            element1.className = 'leekr-extension-toggle';
            document.body.appendChild(element1);

            const element2 = document.createElement('div');
            element2.className = 'other-class';
            document.body.appendChild(element2);

            render(<MoreTab />);
            const powerIcon = screen.getByText('Turn Off');

            act(() => {
                fireEvent.click(powerIcon);
            });

            const externalElements = document.querySelectorAll('.leekr-extension-toggle');
            externalElements.forEach(el => {
                expect(el).toBeInTheDocument();
            });

            document.body.removeChild(element1);
            document.body.removeChild(element2);
        });
    });

    test('clicking Power icon directly toggles the extension', () => {
        (useAppContext as jest.Mock).mockReturnValue({
            data: {
                isExtensionEnabled: true,
            },
            actions: {
                clearAllFindings: mockClearAllFindings,
                toggleExtension: mockToggleExtension,
            },
        });

        render(<MoreTab />);

        const powerIcon = screen.getByText('Disable Extension')
            .closest('.more-tab-card')
            ?.querySelector('.toggle-button svg');

        if (powerIcon) {
            fireEvent.click(powerIcon);
        } else {
            fail('Power icon not found');
        }

        expect(mockToggleExtension).toHaveBeenCalledWith(false);
    });
});