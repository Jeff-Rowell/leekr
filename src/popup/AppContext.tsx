import React, { createContext, useContext, useReducer, useEffect, useState } from "react";
import { Finding } from '../types/findings.types';

interface AppState {
    activeTab: string;
    findings: Finding[];
}

interface AppActions {
    setActiveTab: (tab: string) => void;
    setFindings: (findings: Finding[]) => void;
}

const AppContext = createContext<{ data: AppState; actions: AppActions } | undefined>(undefined);

const initialState: AppState = {
    activeTab: 'Findings',
    findings: [],
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
    };

    useEffect(() => {
        chrome.storage.local.get(['findings'], function (results) {
            if (results.findings && results.findings.length > 0) {
                dispatch({ type: "SET_FINDINGS", payload: results.findings });
            }
            setIsInitialized(true);
        });
    }, []);

    useEffect(() => {
        const handleStorageChange = (changes: { [key: string]: chrome.storage.StorageChange }, area: string) => {
            if (area == "local" && changes.findings) {
                dispatch({ type: "SET_FINDINGS", payload: changes.findings.newValue });
            }
        };

        chrome.storage.onChanged.addListener(handleStorageChange);

        return () => {
            chrome.storage.onChanged.removeListener(handleStorageChange);
        }
    }, []);

    useEffect(() => {
        chrome.storage.local.get(['findings'], function (result) {
            if (result.findings) {
                dispatch({ type: 'SET_FINDIGNS', payload: result.findings })
            }
        });

        const listener = (
            message: { type: string; payload?: any },
            sender: chrome.runtime.MessageSender,
            sendResponse: (response?: any) => void
        ) => {
            if (message.type === 'NEW_FINDINGS') {
                dispatch({ type: 'SET_FINDINGS', payload: message.payload });
            }
        };

        chrome.runtime.onMessage.addListener(listener);

        return () => chrome.runtime.onMessage.removeListener(listener);
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