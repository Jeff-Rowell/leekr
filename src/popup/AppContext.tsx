import React, { createContext, useContext, useReducer, useEffect, useState } from "react";
import { Finding } from '../types/findings.types';
import { PatternsObj } from '../types/patterns.types';
import { retrieveFindings, retrievePatterns } from '../background/utils/common';

interface AppState {
    activeTab: string;
    findings: Finding[];
    patterns: PatternsObj;
    notifications: string;
}

interface AppActions {
    setActiveTab: (tab: string) => void;
    setFindings: (findings: Finding[]) => void;
    setPatterns: (patterns: PatternsObj[]) => void;
    setNotifications: (notifications: string) => void;
    clearNotifications: () => void;
}

const AppContext = createContext<{ data: AppState; actions: AppActions } | undefined>(undefined);

const initialState: AppState = {
    activeTab: 'Findings',
    findings: [],
    patterns: {},
    notifications: '',
};

function appReducer(state: AppState, action: any): AppState {
    switch (action.type) {
        case 'SET_ACTIVE_TAB':
            return {
                ...state,
                activeTab: action.payload,
            };
        case 'SET_FINDINGS':
            return {
                ...state,
                findings: action.payload
            }
        case 'SET_PATTERNS':
            return {
                ...state,
                patterns: action.payload
            }
        case 'SET_NOTIFICATIONS':
            return {
                ...state,
                notifications: action.payload
            }
        case 'CLEAR_NOTIFICATIONS':
            return {
                ...state,
                notifications: ''
            }
        default:
            return state;
    }
}

export function AppProvider({ children }: { children: React.ReactNode }) {
    const [state, dispatch] = useReducer(appReducer, initialState);
    const [isInitialized, setIsInitialized] = useState(false);

    const actions: AppActions = {
        setActiveTab: (tab) => dispatch({ type: 'SET_ACTIVE_TAB', payload: tab }),
        setFindings: (findings) => dispatch({ type: 'SET_FINDINGS', payload: findings }),
        setPatterns: (patterns) => dispatch({ type: 'SET_PATTERNS', payload: patterns }),
        setNotifications: (notifications) => dispatch({ type: 'SET_NOTIFICATIONS', payload: notifications }),
        clearNotifications: () => dispatch({ type: 'CLEAR_NOTIFICATIONS', payload: '' })
    };

    useEffect(() => {
        retrieveFindings().then((resultFindings) => {
            if (resultFindings && resultFindings.length > 0) {
                dispatch({ type: "SET_FINDINGS", payload: resultFindings });
            }
        })
        retrievePatterns().then((resultPatterns) => {
            if (resultPatterns && Object.keys(resultPatterns).length > 0) {
                dispatch({ type: "SET_PATTERNS", payload: resultPatterns });
            }
        })
        chrome.storage.local.get(['notifications'], function (results) {
            if (results.notifications && results.notifications != "0") {
                chrome.action.setBadgeText({ text: results.notifications });
                chrome.action.setBadgeBackgroundColor({ color: '#FF141A' });
                dispatch({ type: 'SET_NOTIFICATIONS', payload: results.notifications });
            } else {
                chrome.action.setBadgeText({ text: '' });
            }
            setIsInitialized(true);
        });

        const handleStorageChange = (changes: { [key: string]: chrome.storage.StorageChange }, area: string) => {
            if (area !== "local") return;

            if (changes.findings) {
                dispatch({ type: "SET_FINDINGS", payload: changes.findings.newValue });
            }

            if (changes.patterns) {
                dispatch({ type: "SET_PATTERNS", payload: changes.patterns.newValue });
            }

            if (changes.notifications) {
                const newNotifications = changes.notifications.newValue;
                dispatch({ type: 'SET_NOTIFICATIONS', payload: newNotifications });

                if (newNotifications !== '' && newNotifications !== '0') {
                    chrome.action.setBadgeText({ text: newNotifications });
                    chrome.action.setBadgeBackgroundColor({ color: '#FF141A' });
                } else {
                    chrome.action.setBadgeText({ text: '' });
                }
            }
        };

        chrome.storage.onChanged.addListener(handleStorageChange);

        return () => {
            chrome.storage.onChanged.removeListener(handleStorageChange);
        };
    }, []);

    useEffect(() => {
        const handleMessage = (
            message: { type: string; payload?: any },
            sender: chrome.runtime.MessageSender,
            sendResponse: (response?: any) => void
        ) => {
            switch (message.type) {
                case 'NEW_FINDINGS':
                    dispatch({ type: 'SET_FINDINGS', payload: message.payload });
                    break;

                case 'NEW_NOTIFICATION':
                    chrome.action.setBadgeText({ text: message.payload });
                    chrome.action.setBadgeBackgroundColor({ color: '#FF141A' });
                    dispatch({ type: 'SET_NOTIFICATIONS', payload: message.payload });
                    break;

                case 'CLEAR_NOTIFICATIONS':
                    chrome.action.setBadgeText({ text: '' });
                    dispatch({ type: 'CLEAR_NOTIFICATIONS', payload: '' });
                    break;
            }
        };

        chrome.runtime.onMessage.addListener(handleMessage);

        return () => {
            chrome.runtime.onMessage.removeListener(handleMessage);
        };
    }, []);

    return (
        <AppContext.Provider value={{ data: state, actions }}>
            {children}
        </AppContext.Provider>
    );
}

export function useAppContext() {
    const context = useContext(AppContext);
    if (context === undefined) {
        throw new Error('useAppContext must be used within an AppProvider');
    }
    return context;
}