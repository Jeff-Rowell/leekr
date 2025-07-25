import { RotateCw, Settings, ShieldCheck, Sparkles } from 'lucide-react';
import React, { useEffect, useRef, useState } from 'react';
import { Finding, ValidityStatus } from 'src/types/findings.types';
import { retrieveFindings, storeFindings } from '../../../../utils/helpers/common';
import { awsValidityHelper } from '../../../../utils/validators/aws/aws_access_keys/awsValidityHelper';
import { awsSessionValidityHelper } from '../../../../utils/validators/aws/aws_session_keys/awsValidityHelper';
import { anthropicValidityHelper } from '../../../../utils/validators/anthropic/anthropicValidityHelper';
import { openaiValidityHelper } from '../../../../utils/validators/openai/openaiValidityHelper';
import { geminiValidityHelper } from '../../../../utils/validators/gemini/geminiValidityHelper';
import { huggingfaceValidityHelper } from '../../../../utils/validators/huggingface/huggingfaceValidityHelper';
import { artifactoryValidityHelper } from '../../../../utils/validators/artifactory/artifactoryValidityHelper';
import { azureOpenAIValidityHelper } from '../../../../utils/validators/azure_openai/azureOpenAIValidityHelper';
import { apolloValidityHelper } from '../../../../utils/validators/apollo/apolloValidityHelper';
import { gcpValidityHelper } from '../../../../utils/validators/gcp/gcpValidityHelper';
import { dockerValidityHelper } from '../../../../utils/validators/docker/dockerValidityHelper';
import { jotformValidityHelper } from '../../../../utils/validators/jotform/jotformValidityHelper';
import { groqValidityHelper } from '../../../../utils/validators/groq/groqValidityHelper';
import { mailgunValidityHelper } from '../../../../utils/validators/mailgun/mailgunValidityHelper';
import { mailchimpValidityHelper } from '../../../../utils/validators/mailchimp/mailchimpValidityHelper';
import { deepseekValidityHelper } from '../../../../utils/validators/deepseek/deepseekValidityHelper';
import { deepaiValidityHelper } from '../../../../utils/validators/deepai/deepaiValidityHelper';
import { telegramBotTokenValidityHelper } from '../../../../utils/validators/telegram_bot_token/telegramBotTokenValidityHelper';
import { rapidApiValidityHelper } from '../../../../utils/validators/rapid_api/rapidApiValidityHelper';
import { makeValidityHelper } from '../../../../utils/validators/make/api_token/makeValidityHelper';
import { makeMcpValidityHelper } from '../../../../utils/validators/make/mcp_token/makeMcpValidityHelper';
import { useAppContext } from '../../../AppContext';
import ModalHeader from '../../modalheader/ModalHeader';
import './style.css';

const FindingsTab: React.FC = () => {
    const { data: { findings } } = useAppContext();
    const [activeSettingsMenu, setActiveSettingsMenu] = useState<{ index: number, finding: Finding } | null>(null);
    const settingsButtonRefs = useRef<(HTMLButtonElement | null)[]>([]);
    const settingsDropdownRef = useRef<HTMLDivElement>(null);
    const [dropdownPosition, setDropdownPosition] = useState({ top: 0, left: 0 });
    const [viewedFindings, setViewedFindings] = useState(false);
    const [isRechecking, setIsRechecking] = useState(false);
    const [recheckProgress, setRecheckProgress] = useState({ current: 0, total: 0 });


    const handleValidityCheck = async (finding: Finding) => {
        try {
            if (finding.secretType === "AWS Access & Secret Keys") {
                await awsValidityHelper(finding);
            } else if (finding.secretType === "AWS Session Keys") {
                await awsSessionValidityHelper(finding);
            } else if (finding.secretType === "Anthropic AI") {
                await anthropicValidityHelper(finding);
            } else if (finding.secretType === "OpenAI") {
                await openaiValidityHelper(finding);
            } else if (finding.secretType === "Gemini") {
                await geminiValidityHelper(finding);
            } else if (finding.secretType === "Hugging Face") {
                await huggingfaceValidityHelper(finding);
            } else if (finding.secretType === "Artifactory") {
                await artifactoryValidityHelper(finding);
            } else if (finding.secretType === "Azure OpenAI") {
                await azureOpenAIValidityHelper(finding);
            } else if (finding.secretType === "Apollo") {
                await apolloValidityHelper(finding);
            } else if (finding.secretType === "Google Cloud Platform") {
                await gcpValidityHelper(finding);
            } else if (finding.secretType === "Docker") {
                await dockerValidityHelper(finding);
            } else if (finding.secretType === "JotForm") {
                await jotformValidityHelper(finding);
            } else if (finding.secretType === "Groq") {
                await groqValidityHelper(finding);
            } else if (finding.secretType === "Mailgun") {
                await mailgunValidityHelper(finding);
            } else if (finding.secretType === "Mailchimp") {
                await mailchimpValidityHelper(finding);
            } else if (finding.secretType === "DeepSeek") {
                await deepseekValidityHelper(finding);
            } else if (finding.secretType === "DeepAI") {
                await deepaiValidityHelper(finding);
            } else if (finding.secretType === "Telegram Bot Token") {
                await telegramBotTokenValidityHelper(finding);
            } else if (finding.secretType === "RapidAPI") {
                await rapidApiValidityHelper(finding);
            } else if (finding.secretType === "Make") {
                await makeValidityHelper(finding);
            } else if (finding.secretType === "Make MCP") {
                await makeMcpValidityHelper(finding);
            }
        } catch (error) {
            console.error(`Validity check failed for ${finding.secretType}:`, error);
        }
    };

    const handleRecheckAll = async () => {
        setIsRechecking(true);
        setRecheckProgress({ current: 0, total: findings.length });

        // Create concurrent validation promises
        const validationPromises = findings.map(async (finding) => {
            await handleValidityCheck(finding);
            // Update progress using functional state update to avoid race conditions
            setRecheckProgress(prev => ({ 
                current: prev.current + 1, 
                total: prev.total 
            }));
        });

        // Wait for all validations to complete
        await Promise.all(validationPromises);
        setIsRechecking(false);
    };

    React.useEffect(() => {
        chrome.action.setBadgeText({ text: '' });
        chrome.storage.local.set({ "notifications": '' }, function () {
            chrome.runtime.sendMessage({
                type: 'CLEAR_NOTIFICATIONS',
                payload: ''
            }).catch(() => { });
        });

        // Mark all findings as viewed after a delay to let user see the highlighting
        const markFindingsAsViewed = async () => {
            const existingFindings = await retrieveFindings();
            const hasNewFindings = existingFindings.some(finding => finding.isNew === true);
            
            if (hasNewFindings) {
                // Wait 3 seconds to let user see the highlighting, then clear it
                setTimeout(async () => {
                    const updatedFindings = existingFindings.map(finding => ({
                        ...finding,
                        isNew: false
                    }));
                    await storeFindings(updatedFindings);
                    setViewedFindings(true);
                }, 3000);
            }
        };

        markFindingsAsViewed();
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
                const dropdownHeight = 175;
                const spaceBelow = window.innerHeight - rect.bottom;
                const spaceAbove = rect.top;
                const showAbove = spaceBelow < dropdownHeight && spaceAbove > dropdownHeight;
                
                setDropdownPosition({
                    top: showAbove ? rect.top - dropdownHeight + window.scrollY : rect.bottom + window.scrollY,
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
                                <th>
                                    {findings.length > 0 && (
                                        <div className="recheck-all-header">
                                            <button
                                                className="recheck-all-button-header tooltip"
                                                onClick={handleRecheckAll}
                                                disabled={isRechecking}
                                                aria-label="Recheck all findings"
                                            >
                                                <RotateCw size={16} className={`recheck-icon ${isRechecking ? 'spinning' : ''}`} />
                                                <span className="tooltip-text">
                                                    {isRechecking ? 'Rechecking validity...' : 'Recheck the validity of all findings'}
                                                </span>
                                            </button>
                                        </div>
                                    )}
                                </th>
                            </tr>
                        </thead>
                        {isRechecking && (
                            <tbody>
                                <tr>
                                    <td colSpan={4} className="status-bar-container">
                                        <div className="recheck-status-bar">
                                            <div className="status-bar-content">
                                                <span className="status-text">
                                                    Rechecking validity... ({recheckProgress.current}/{recheckProgress.total})
                                                </span>
                                                <div className="progress-bar">
                                                    <div 
                                                        className="progress-fill"
                                                        style={{
                                                            width: `${(recheckProgress.current / recheckProgress.total) * 100}%`
                                                        }}
                                                    />
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        )}
                        <tbody>
                            {[...findings]
                                .sort((a, b) => {
                                    // Sort by isNew first (new findings at top)
                                    if (a.isNew && !b.isNew) return -1;
                                    if (!a.isNew && b.isNew) return 1;
                                    
                                    // Then sort by discoveredAt (newest first)
                                    if (a.discoveredAt && b.discoveredAt) {
                                        return new Date(b.discoveredAt).getTime() - new Date(a.discoveredAt).getTime();
                                    }
                                    if (a.discoveredAt && !b.discoveredAt) return -1;
                                    
                                    // Finally, sort by secretType alphabetically
                                    return a.secretType.localeCompare(b.secretType);
                                })
                                .map((finding, index) => {
                                    const newFindingStyle = {
                                        backgroundColor: 'rgba(46, 204, 113, 0.2)',
                                        borderLeft: '3px solid #2ecc71',
                                        fontWeight: '600',
                                        color: '#2ecc71'
                                    };
                                    
                                    const shouldHighlight = finding.isNew === true && !viewedFindings;
                                    
                                    return (
                                <tr 
                                    key={index} 
                                    className={shouldHighlight ? 'new-finding-row' : ''}
                                    style={shouldHighlight ? newFindingStyle : {}}
                                >
                                    <td className="findings-td" style={shouldHighlight ? { fontWeight: '600', color: '#2ecc71' } : {}}>
                                        <div className="secret-type-container">
                                            {shouldHighlight && (
                                                <div className="new-indicator">
                                                    <Sparkles size={14} className="new-icon" />
                                                    <span className="new-text">NEW</span>
                                                </div>
                                            )}
                                            <div className="secret-type-text">{finding.secretType}</div>
                                        </div>
                                    </td>
                                    <td className="validity-cell" style={shouldHighlight ? { fontWeight: '600', color: '#2ecc71' } : {}}>
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
                                    <td className="findings-td" style={shouldHighlight ? { fontWeight: '600', color: '#2ecc71' } : {}}>{finding.numOccurrences}</td>
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
                                    );
                                })
                            }
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