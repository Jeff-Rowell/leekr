import React from 'react';
import { render, renderHook, act, waitFor } from '@testing-library/react';
import { AppProvider, useAppContext } from './AppContext';
import { Finding } from '../types/findings.types';
import { PatternsObj } from '../types/patterns.types';
import { Suffix } from '../types/suffix.types';
import * as helpers from '../utils/helpers/common';

jest.mock('../utils/helpers/common', () => ({
    retrieveFindings: jest.fn(),
    retrievePatterns: jest.fn(),
}));

const mockChrome = {
    storage: {
        local: {
            get: jest.fn(),
            set: jest.fn(),
            onChanged: {
                addListener: jest.fn(),
                removeListener: jest.fn(),
            },
        },
        onChanged: {
            addListener: jest.fn(),
            removeListener: jest.fn(),
        },
    },
    action: {
        setBadgeText: jest.fn(),
        setBadgeBackgroundColor: jest.fn(),
    },
    runtime: {
        onMessage: {
            addListener: jest.fn(),
            removeListener: jest.fn(),
        },
    },
};

// @ts-ignore
global.chrome = mockChrome;

Object.defineProperty(global, 'crypto', {
    value: {
        randomUUID: jest.fn(() => 'mock-uuid-' + Math.random()),
    },
});

describe('AppContext', () => {
    const mockFindings: Finding[] = [
        {
            numOccurrences: 1,
            secretType: 'api-key',
            secretValue: { value: 'test-secret' },
            validity: 'unknown',
            fingerprint: 'test-fingerprint',
            occurrences: new Set([
                {
                    secretType: 'api-key',
                    fingerprint: 'test-fingerprint',
                    secretValue: { value: 'test-secret' },
                    filePath: '/test/file.js',
                    url: 'https://example.com/file.js',
                    sourceContent: {
                        content: 'const apiKey = "test-secret";',
                        contentFilename: 'file.js',
                        contentStartLineNum: 1,
                        contentEndLineNum: 1,
                        exactMatchNumbers: [1],
                    },
                },
            ]),
        },
    ];

    const mockPatterns: PatternsObj = {
        'api-key': {
            name: 'API Key',
            familyName: 'Generic',
            isValidityCustomizable: true,
            hasCustomValidity: false,
            validityEndpoints: [],
            pattern: /api[_-]?key/gi,
            entropy: 3.5,
            global: true,
        },
    };

    const mockSuffixes: Suffix[] = [
        { id: 'suffix-1', value: '.js', isDefault: true },
        { id: 'suffix-2', value: '.ts', isDefault: false },
    ];

    beforeEach(() => {
        jest.clearAllMocks();

        mockChrome.storage.local.get.mockImplementation((keys, callback) => {
            callback({});
        });

        (helpers.retrieveFindings as jest.Mock).mockResolvedValue([]);
        (helpers.retrievePatterns as jest.Mock).mockResolvedValue({});
    });

    describe('AppProvider initialization', () => {
        test('should initialize with default state', async () => {
            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(result.current.data.activeTab).toBe('Findings');
                expect(result.current.data.findings).toEqual([]);
                expect(result.current.data.patterns).toEqual({});
                expect(result.current.data.notifications).toBe('');
                expect(result.current.data.customSuffixesEnabled).toBe(false);
                expect(result.current.data.isExtensionEnabled).toBe(true);
                expect(result.current.data.suffixes).toHaveLength(3);
                expect(result.current.data.suffixes[0].value).toBe('.js');
            });
        });

        test('should load findings from storage on initialization', async () => {
            (helpers.retrieveFindings as jest.Mock).mockResolvedValue(mockFindings);

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(result.current.data.findings).toEqual(mockFindings);
            });
        });

        test('should load patterns from storage on initialization', async () => {
            (helpers.retrievePatterns as jest.Mock).mockResolvedValue(mockPatterns);

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(result.current.data.patterns).toEqual(mockPatterns);
            });
        });

        test('should load notifications from chrome storage', async () => {
            mockChrome.storage.local.get.mockImplementation((keys, callback) => {
                if (keys.includes('notifications')) {
                    callback({ notifications: '5' });
                } else {
                    callback({});
                }
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(result.current.data.notifications).toBe('5');
                expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '5' });
                expect(mockChrome.action.setBadgeBackgroundColor).toHaveBeenCalledWith({ color: '#FF141A' });
            });
        });

        test('should load custom suffixes from chrome storage', async () => {
            mockChrome.storage.local.get.mockImplementation((keys, callback) => {
                if (keys.includes('suffixes')) {
                    callback({ suffixes: mockSuffixes });
                } else if (keys.includes('customSuffixesEnabled')) {
                    callback({ customSuffixesEnabled: true });
                } else {
                    callback({});
                }
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(result.current.data.suffixes).toEqual(mockSuffixes);
                expect(result.current.data.customSuffixesEnabled).toBe(true);
            });
        });

        test('should load extension enabled state from chrome storage', async () => {
            mockChrome.storage.local.get.mockImplementation((keys, callback) => {
                if (keys.includes('isExtensionEnabled')) {
                    callback({ isExtensionEnabled: false });
                } else {
                    callback({});
                }
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(result.current.data.isExtensionEnabled).toBe(false);
                expect(result.current.data.activeTab).toBe('More');
            });
        });
    });

    describe('Actions', () => {
        let wrapper: ({ children }: { children: React.ReactNode }) => React.ReactElement;
        let result: any;

        beforeEach(async () => {
            wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const hookResult = renderHook(() => useAppContext(), { wrapper });
            result = hookResult.result;

            await waitFor(() => {
                expect(result.current).toBeDefined();
            });
        });

        test('should set active tab', () => {
            act(() => {
                result.current.actions.setActiveTab('Patterns');
            });

            expect(result.current.data.activeTab).toBe('Patterns');
        });

        test('should set findings', () => {
            act(() => {
                result.current.actions.setFindings(mockFindings);
            });

            expect(result.current.data.findings).toEqual(mockFindings);
        });

        test('should set patterns', () => {
            act(() => {
                result.current.actions.setPatterns(mockPatterns);
            });

            expect(result.current.data.patterns).toEqual(mockPatterns);
        });

        test('should set notifications', () => {
            act(() => {
                result.current.actions.setNotifications('3');
            });

            expect(result.current.data.notifications).toBe('3');
        });

        test('should set suffixes and save to chrome storage', () => {
            act(() => {
                result.current.actions.setSuffixes(mockSuffixes);
            });

            expect(result.current.data.suffixes).toEqual(mockSuffixes);
            expect(mockChrome.storage.local.set).toHaveBeenCalledWith({ suffixes: mockSuffixes });
        });

        test('should set custom suffixes enabled and save to chrome storage', () => {
            act(() => {
                result.current.actions.setCustomSuffixesEnabled(true);
            });

            expect(result.current.data.customSuffixesEnabled).toBe(true);
            expect(mockChrome.storage.local.set).toHaveBeenCalledWith({ customSuffixesEnabled: true });
        });

        test('should clear notifications', () => {
            act(() => {
                result.current.actions.setNotifications('5');
            });

            expect(result.current.data.notifications).toBe('5');

            act(() => {
                result.current.actions.clearNotifications();
            });

            expect(result.current.data.notifications).toBe('');
        });

        test('should clear all findings', () => {
            act(() => {
                result.current.actions.setFindings(mockFindings);
            });

            expect(result.current.data.findings).toEqual(mockFindings);

            act(() => {
                result.current.actions.clearAllFindings();
            });

            expect(result.current.data.findings).toEqual([]);
            expect(mockChrome.storage.local.set).toHaveBeenCalledWith({ findings: [] });
        });

        test('should toggle extension and save to chrome storage', () => {
            act(() => {
                result.current.actions.toggleExtension(false);
            });

            expect(result.current.data.isExtensionEnabled).toBe(false);
            expect(result.current.data.activeTab).toBe('More');
            expect(mockChrome.storage.local.set).toHaveBeenCalledWith({ isExtensionEnabled: false });

            act(() => {
                result.current.actions.toggleExtension(true);
            });

            expect(result.current.data.isExtensionEnabled).toBe(true);
            expect(mockChrome.storage.local.set).toHaveBeenCalledWith({ isExtensionEnabled: true });
        });
    });

    describe('Storage change listener', () => {
        test('should handle findings storage changes', async () => {
            let storageChangeHandler: any;

            mockChrome.storage.onChanged.addListener.mockImplementation((handler) => {
                storageChangeHandler = handler;
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(mockChrome.storage.onChanged.addListener).toHaveBeenCalled();
            });

            act(() => {
                storageChangeHandler(
                    {
                        findings: { newValue: mockFindings },
                    },
                    'local'
                );
            });

            expect(result.current.data.findings).toEqual(mockFindings);
        });

        test('should handle patterns storage changes', async () => {
            let storageChangeHandler: any;

            mockChrome.storage.onChanged.addListener.mockImplementation((handler) => {
                storageChangeHandler = handler;
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(mockChrome.storage.onChanged.addListener).toHaveBeenCalled();
            });

            act(() => {
                storageChangeHandler(
                    {
                        patterns: { newValue: mockPatterns },
                    },
                    'local'
                );
            });

            expect(result.current.data.patterns).toEqual(mockPatterns);
        });

        test('should handle notifications storage changes and update badge', async () => {
            let storageChangeHandler: any;

            mockChrome.storage.onChanged.addListener.mockImplementation((handler) => {
                storageChangeHandler = handler;
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(mockChrome.storage.onChanged.addListener).toHaveBeenCalled();
            });

            act(() => {
                storageChangeHandler(
                    {
                        notifications: { newValue: '7' },
                    },
                    'local'
                );
            });

            expect(result.current.data.notifications).toBe('7');
            expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '7' });
            expect(mockChrome.action.setBadgeBackgroundColor).toHaveBeenCalledWith({ color: '#FF141A' });

            act(() => {
                storageChangeHandler(
                    {
                        notifications: { newValue: '0' },
                    },
                    'local'
                );
            });

            expect(result.current.data.notifications).toBe('0');
            expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
        });

        test('should ignore non-local storage changes', async () => {
            let storageChangeHandler: any;

            mockChrome.storage.onChanged.addListener.mockImplementation((handler) => {
                storageChangeHandler = handler;
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(mockChrome.storage.onChanged.addListener).toHaveBeenCalled();
            });

            const initialFindings = result.current.data.findings;

            act(() => {
                storageChangeHandler(
                    {
                        findings: { newValue: mockFindings },
                    },
                    'sync'
                );
            });

            expect(result.current.data.findings).toEqual(initialFindings);
        });
    });

    describe('Runtime message listener', () => {
        test('should handle NEW_FINDINGS message', async () => {
            let messageHandler: any;

            mockChrome.runtime.onMessage.addListener.mockImplementation((handler) => {
                messageHandler = handler;
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(mockChrome.runtime.onMessage.addListener).toHaveBeenCalled();
            });

            act(() => {
                messageHandler(
                    { type: 'NEW_FINDINGS', payload: mockFindings },
                    {},
                    jest.fn()
                );
            });

            expect(result.current.data.findings).toEqual(mockFindings);
        });

        test('should handle NEW_NOTIFICATION message', async () => {
            let messageHandler: any;

            mockChrome.runtime.onMessage.addListener.mockImplementation((handler) => {
                messageHandler = handler;
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(mockChrome.runtime.onMessage.addListener).toHaveBeenCalled();
            });

            act(() => {
                messageHandler(
                    { type: 'NEW_NOTIFICATION', payload: '4' },
                    {},
                    jest.fn()
                );
            });

            expect(result.current.data.notifications).toBe('4');
            expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '4' });
            expect(mockChrome.action.setBadgeBackgroundColor).toHaveBeenCalledWith({ color: '#FF141A' });
        });

        test('should handle CLEAR_NOTIFICATIONS message', async () => {
            let messageHandler: any;

            mockChrome.runtime.onMessage.addListener.mockImplementation((handler) => {
                messageHandler = handler;
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            act(() => {
                result.current.actions.setNotifications('5');
            });

            await waitFor(() => {
                expect(mockChrome.runtime.onMessage.addListener).toHaveBeenCalled();
            });

            act(() => {
                messageHandler(
                    { type: 'CLEAR_NOTIFICATIONS' },
                    {},
                    jest.fn()
                );
            });

            expect(result.current.data.notifications).toBe('');
            expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
        });

        test('should handle unknown action types by returning unchanged state', async () => {
            const mockDispatch = jest.fn();
            const originalUseReducer = React.useReducer;

            jest.spyOn(React, 'useReducer').mockImplementation((reducer, initialState) => {
                const [state, dispatch] = originalUseReducer(reducer, initialState);
                mockDispatch.mockImplementation(dispatch);
                return [state, mockDispatch];
            });

            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            await waitFor(() => {
                expect(result.current).toBeDefined();
            });

            const initialState = { ...result.current.data };

            act(() => {
                mockDispatch({ type: 'UNKNOWN_ACTION_TYPE', payload: 'test' });
            });

            expect(result.current.data).toEqual(initialState);

            (React.useReducer as jest.Mock).mockRestore();
        });
    });

    describe('useAppContext hook', () => {
        test('should throw error when used outside AppProvider', () => {
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            expect(() => {
                renderHook(() => useAppContext());
            }).toThrow('useAppContext must be used within an AppProvider');

            consoleSpy.mockRestore();
        });

        test('should return context when used within AppProvider', () => {
            const wrapper = ({ children }: { children: React.ReactNode }) => (
                <AppProvider>{children}</AppProvider>
            );

            const { result } = renderHook(() => useAppContext(), { wrapper });

            expect(result.current).toBeDefined();
            expect(result.current.data).toBeDefined();
            expect(result.current.actions).toBeDefined();
        });
    });

    describe('Component cleanup', () => {
        test('should remove event listeners on unmount', () => {
            const { unmount } = render(<AppProvider><div>Test</div></AppProvider>);

            unmount();

            expect(mockChrome.storage.onChanged.removeListener).toHaveBeenCalled();
            expect(mockChrome.runtime.onMessage.removeListener).toHaveBeenCalled();
        });
    });
});