import { RotateCw, Settings, ShieldCheck } from 'lucide-react';
import React, { useEffect, useRef, useState } from 'react';
import { Finding, ValidityStatus } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../../../utils/helpers/common';
import { awsValidityHelper } from '../../../../utils/validators/aws/aws_access_keys/awsValidityHelper';
import { awsSessionValidityHelper } from '../../../../utils/validators/aws/aws_session_keys/awsValidityHelper';
import { anthropicValidityHelper } from '../../../../utils/validators/anthropic/anthropicValidityHelper';
import { openaiValidityHelper } from '../../../../utils/validators/openai/openaiValidityHelper';
import { useAppContext } from '../../../AppContext';
import ModalHeader from '../../modalheader/ModalHeader';
import './style.css';

const FindingsTab: React.FC = () => {
    const { data: { findings } } = useAppContext();
    const [activeSettingsMenu, setActiveSettingsMenu] = useState<{ index: number, finding: Finding } | null>(null);
    const settingsButtonRefs = useRef<(HTMLButtonElement | null)[]>([]);
    const settingsDropdownRef = useRef<HTMLDivElement>(null);
    const [dropdownPosition, setDropdownPosition] = useState({ top: 0, left: 0 });

    const handleValidityCheck = async (finding: Finding) => {
        if (finding.secretType === "AWS Access & Secret Keys") {
            awsValidityHelper(finding);
        } else if (finding.secretType === "AWS Session Keys") {
            awsSessionValidityHelper(finding);
        } else if (finding.secretType === "Anthropic AI") {
            anthropicValidityHelper(finding);
        } else if (finding.secretType === "OpenAI") {
            openaiValidityHelper(finding);
        }
    };

    React.useEffect(() => {
        chrome.action.setBadgeText({ text: '' });
        chrome.storage.local.set({ "notifications": '' }, function () {
            chrome.runtime.sendMessage({
                type: 'CLEAR_NOTIFICATIONS',
                payload: ''
            }).catch(() => { });
        });
    }, []);

    const getValidityColorClass = (validity: ValidityStatus): string => {
        switch (validity) {
            case 'valid': return 'validity-valid';
            case 'invalid': return 'validity-invalid';
            case 'failed_to_check': return 'validity-failed';
            case 'unknown':
            default: return 'validity-unknown';
        }
    };

    const toggleSettingsMenu = (index: number, finding: Finding, e: React.MouseEvent) => {
        e.stopPropagation();

        if (activeSettingsMenu !== null && activeSettingsMenu.index === index) {
            setActiveSettingsMenu(null);
        } else {
            const buttonElement = settingsButtonRefs.current[index];
            if (buttonElement) {
                const rect = buttonElement.getBoundingClientRect();
                setDropdownPosition({
                    top: rect.bottom + window.scrollY,
                    left: rect.right - 250 + window.scrollX // 250px is the width of the dropdown
                });
            }
            setActiveSettingsMenu({ index, finding });
        }
    };

    const closeSettingsMenu = () => {
        setActiveSettingsMenu(null);
    };

    // Close the settings menu when clicking outside
    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            const clickedSettingsButton = settingsButtonRefs.current.some(
                ref => ref && ref.contains(event.target as Node)
            );

            if (
                activeSettingsMenu !== null &&
                settingsDropdownRef.current &&
                !settingsDropdownRef.current.contains(event.target as Node) &&
                !clickedSettingsButton
            ) {
                setActiveSettingsMenu(null);
            }
        };

        if (activeSettingsMenu !== null) {
            document.addEventListener('mousedown', handleClickOutside);
        }

        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [activeSettingsMenu]);

    // Handle settings option click
    const handleSettingsOptionClick = (option: string, activeMenu: { index: number, finding: Finding }) => {
        if (option === "Report Issue") {
            window.open("https://github.com/Jeff-Rowell/Leekr/issues/new", "_blank");
        } else if (option === "Delete Finding") {
            retrieveFindings().then((existingFindings) => {
                const index = existingFindings.findIndex(
                    (f) => f.fingerprint === activeMenu.finding.fingerprint
                );
                existingFindings.splice(index, 1);
                storeFindings(existingFindings);
            });
        } else if (option === "View Occurrences") {
            const url = chrome.runtime.getURL("options.html") +
                `?tab=findings&fingerprint=${activeMenu.finding.fingerprint}`;
            chrome.tabs.create({ url });
        }

        setActiveSettingsMenu(null);
    };

    return (
        <section className="findings-tab">
            <div className="findings-section">
                <div className="findings-table-container">
                    <table className="findings-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Validity</th>
                                <th>Occurrences</th>
                                <th>{/* Empty header for settings column */}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {findings.map((finding, index) => (
                                <tr key={index}>
                                    <td className="findings-td">{finding.secretType}</td>
                                    <td className="validity-cell">
                                        <div className={`validity-status ${getValidityColorClass(finding.validity)}`}>
                                            {finding.validity.replace(/_/g, ' ')}

                                            {finding.validatedAt && (
                                                <div className="validity-info tooltip">
                                                    <ShieldCheck size={16} />
                                                    <span className="tooltip-text">
                                                        Last Checked: {new Date(finding.validatedAt).toLocaleString()}
                                                        <button
                                                            className="recheck-button"
                                                            onClick={() => handleValidityCheck(finding)}
                                                            aria-label="Recheck validity"
                                                        >
                                                            <RotateCw size={14} />
                                                        </button>
                                                    </span>
                                                </div>
                                            )}

                                        </div>
                                    </td>
                                    <td className="findings-td">{finding.numOccurrences}</td>
                                    <td className="settings-cell">
                                        <div className="settings-container">
                                            <button
                                                ref={el => { settingsButtonRefs.current[index] = el; }}
                                                className="settings-button"
                                                onClick={(e) => toggleSettingsMenu(index, finding, e)}
                                                aria-label="Settings"
                                            >
                                                <Settings size={16} className="settings-icon" />
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Render dropdown outside of table for proper z-index handling */}
            {activeSettingsMenu !== null && (
                <div
                    className="download-options settings-dropdown shadow-md rounded border z-10"
                    ref={settingsDropdownRef}
                    style={{
                        top: `${dropdownPosition.top}px`,
                        left: `${dropdownPosition.left}px`
                    }}
                >
                    <ModalHeader title="Finding Options" onClose={closeSettingsMenu} />
                    <div className="settings-options">
                        <button onClick={() => handleSettingsOptionClick("View Occurrences", activeSettingsMenu)}>
                            View Occurrences
                        </button>
                        <button onClick={() => handleSettingsOptionClick("Delete Finding", activeSettingsMenu)}>
                            Delete Finding
                        </button>
                        <button onClick={() => handleSettingsOptionClick("Report Issue", activeSettingsMenu)}>
                            Report Issue
                        </button>
                    </div>
                </div>
            )}
        </section>
    );
};

export default FindingsTab;