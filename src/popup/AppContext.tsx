import React, { createContext, useContext, useCallback, useEffect, useState } from "react";
import { Findings } from '../models/Findings';
import { FindingsState, FindingsAction, FindingsContext } from '../types/app.types';

const sharedFindings = new Findings();
const AppContext = createContext<FindingsContext | undefined>(undefined);

function findingsReducer(state: FindingsState, action: FindingsAction): FindingsState {
    switch (action.type) {
        case 'SET_ACTIVE_TAB':
            return {
                ...state,
                activeTab: action.tab,
            };
        case 'SET_FINDINGS':
            return {
                ...state,
                findings: {
                    ...state.findings,
                    ...action.findings
                }
            }
        case 'SET_NOTIFICATIONS':
            return {
                ...state,
                notifications: action.notifications
            }
        case 'CLEAR_NOTIFICATIONS':
            return {
                ...state
            }
        default:
            return state;
    }
}

export function AppProvider({ children }: { children: React.ReactNode }) {
    const [state, setState] = useState<FindingsState>(sharedFindings.getState());

    const dispatch = useCallback((action: FindingsAction) => {
        const newState = findingsReducer(sharedFindings.getState(), action);
        sharedFindings.updateState(newState);
        setState(newState);
    }, []);

    useEffect(() => {
        const handleStorageChange = (changes: { [key: string]: chrome.storage.StorageChange }, area: string) => {
            if (area !== "local") return;

            if (changes.findings) {
                dispatch({ type: "SET_FINDINGS", findings: changes.findings.newValue });
            }

            if (changes.notifications) {
                const newNotifications = changes.notifications.newValue;
                dispatch({ type: 'SET_NOTIFICATIONS', notifications: newNotifications });

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
            message: { type: string; payload?: any }
        ) => {
            switch (message.type) {
                case 'NEW_FINDINGS':
                    dispatch({ type: 'SET_FINDINGS', findings: message.payload });
                    break;

                case 'NEW_NOTIFICATION':
                    dispatch({ type: 'SET_NOTIFICATIONS', notifications: message.payload });
                    break;

                case 'CLEAR_NOTIFICATIONS':
                    chrome.action.setBadgeText({ text: '' });
                    dispatch({ type: 'CLEAR_NOTIFICATIONS', notifications: '' });
                    break;
            }
        };

        chrome.runtime.onMessage.addListener(handleMessage);

        return () => {
            chrome.runtime.onMessage.removeListener(handleMessage);
        };
    }, []);

    return (
        <AppContext.Provider value={{ state: state, dispatch }}>
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