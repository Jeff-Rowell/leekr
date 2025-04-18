import React, { createContext, useContext, useReducer, useEffect, useState } from "react";
import { Finding } from '../types/findings.types';

interface AppState {
    activeTab: string;
    findings: Finding[];
    notifications: string;
}

interface AppActions {
    setActiveTab: (tab: string) => void;
    setFindings: (findings: Finding[]) => void;
    setNotifications: (notifications: string) => void;
    clearNotifications: () => void;
}

const AppContext = createContext<{ data: AppState; actions: AppActions } | undefined>(undefined);

const initialState: AppState = {
    activeTab: 'Findings',
    findings: [],
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
        setNotifications: (notifications) => dispatch({ type: 'SET_NOTIFICATIONS', payload: notifications }),
        clearNotifications: () => dispatch({ type: 'CLEAR_NOTIFICATIONS', payload: '' })
    };

    useEffect(() => {
        chrome.storage.local.get(['findings', 'notifications'], function (results) {
            if (results.findings && results.findings.length > 0) {
                dispatch({ type: "SET_FINDINGS", payload: results.findings });
            }

            if (results.notifications) {
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

            if (changes.notifications) {
                const newNotifications = changes.notifications.newValue;
                dispatch({ type: 'SET_NOTIFICATIONS', payload: newNotifications });

                if (newNotifications !== '') {
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
                    console.log('Received new findings: ', message.payload);
                    dispatch({ type: 'SET_FINDINGS', payload: message.payload });
                    break;

                case 'NEW_NOTIFICATION':
                    console.log('Setting badge to:', message.payload);
                    chrome.action.setBadgeText({ text: message.payload });
                    chrome.action.setBadgeBackgroundColor({ color: '#FF141A' });
                    dispatch({ type: 'SET_NOTIFICATIONS', payload: message.payload });
                    break;

                case 'CLEAR_NOTIFICATIONS':
                    console.log('Clearing notifications badge');
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