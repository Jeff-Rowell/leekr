import { Finding, FindingDict } from './findings.types';

export interface FindingsState {
    activeTab: string;
    findings: Finding[];
    findingsMap: FindingDict[];
    notifications: string;
}

export type FindingsAction =
    | { type: 'SET_ACTIVE_TAB'; tab: string }
    | { type: 'SET_FINDINGS'; findings: Finding[] }
    | { type: 'SET_NOTIFICATIONS'; notifications: string }
    | { type: 'CLEAR_NOTIFICATIONS'; notifications: '' }

export interface FindingsContext {
    state: FindingsState;
    dispatch: (action: FindingsAction) => void;
}