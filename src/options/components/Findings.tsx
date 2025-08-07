import {
    AlertTriangle,
    ChevronDown,
    ChevronLeft,
    ChevronRight,
    ChevronUp,
    RefreshCw,
    RotateCw,
    ShieldCheck,
    SquareArrowRight
} from 'lucide-react';
import React, { useEffect, useState } from 'react';
import { useAppContext } from '../../popup/AppContext';
import { Finding, ValidityStatus } from '../../types/findings.types';
import { awsValidityHelper } from '../../utils/validators/aws/aws_access_keys/awsValidityHelper';
import { awsSessionValidityHelper } from '../../utils/validators/aws/aws_session_keys/awsValidityHelper';
import { anthropicValidityHelper } from '../../utils/validators/anthropic/anthropicValidityHelper';
import { openaiValidityHelper } from '../../utils/validators/openai/openaiValidityHelper';
import { geminiValidityHelper } from '../../utils/validators/gemini/geminiValidityHelper';
import { huggingfaceValidityHelper } from '../../utils/validators/huggingface/huggingfaceValidityHelper';
import { artifactoryValidityHelper } from '../../utils/validators/artifactory/artifactoryValidityHelper';
import { azureOpenAIValidityHelper } from '../../utils/validators/azure_openai/azureOpenAIValidityHelper';
import { apolloValidityHelper } from '../../utils/validators/apollo/apolloValidityHelper';
import { gcpValidityHelper } from '../../utils/validators/gcp/gcpValidityHelper';
import { dockerValidityHelper } from '../../utils/validators/docker/dockerValidityHelper';
import { jotformValidityHelper } from '../../utils/validators/jotform/jotformValidityHelper';
import { groqValidityHelper } from '../../utils/validators/groq/groqValidityHelper';
import { mailgunValidityHelper } from '../../utils/validators/mailgun/mailgunValidityHelper';
import { mailchimpValidityHelper } from '../../utils/validators/mailchimp/mailchimpValidityHelper';
import { deepseekValidityHelper } from '../../utils/validators/deepseek/deepseekValidityHelper';
import { deepaiValidityHelper } from '../../utils/validators/deepai/deepaiValidityHelper';
import { telegramBotTokenValidityHelper } from '../../utils/validators/telegram_bot_token/telegramBotTokenValidityHelper';
import { rapidApiValidityHelper } from '../../utils/validators/rapid_api/rapidApiValidityHelper';
import { makeValidityHelper } from '../../utils/validators/make/api_token/makeValidityHelper';
import { makeMcpValidityHelper } from '../../utils/validators/make/mcp_token/makeMcpValidityHelper';
import { langsmithValidityHelper } from '../../utils/validators/langsmith/langsmithValidityHelper';
import { slackValidityHelper } from '../../utils/validators/slack/slackValidityHelper';
import { paypalOAuthValidityHelper } from '../../utils/validators/paypal_oauth/paypalOAuthValidityHelper';

// Pagination constants
const ITEMS_PER_PAGE = 10;

export const Findings: React.FC = () => {
    const { data } = useAppContext();
    const [currentPage, setCurrentPage] = useState(1);
    const [filteredFindings, setFilteredFindings] = useState<Finding[]>([]);
    const [validityFilter, setValidityFilter] = useState<ValidityStatus | 'all'>('all');
    const [typeFilter, setTypeFilter] = useState<string>('');
    const [sortField, setSortField] = useState<'secretType' | 'numOccurrences' | 'validity'>('secretType');
    const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
    const [isRechecking, setIsRechecking] = useState(false);
    const [recheckProgress, setRecheckProgress] = useState({ current: 0, total: 0 });

    // Get all unique secret types for the filter dropdown
    const uniqueSecretTypes = Array.from(new Set(data.findings.map(f => f.secretType)));

    useEffect(() => {
        // Apply filters and sorting
        let results = [...data.findings];

        // Filter by validity
        if (validityFilter !== 'all') {
            results = results.filter(finding => finding.validity === validityFilter);
        }

        // Filter by secret type
        if (typeFilter) {
            results = results.filter(finding => finding.secretType === typeFilter);
        }
        // Apply sorting
        results.sort((a, b) => {
            if (sortField === 'secretType') {
                return sortDirection === 'asc'
                    ? a.secretType.localeCompare(b.secretType)
                    : b.secretType.localeCompare(a.secretType);
            } else if (sortField === 'numOccurrences') {
                return sortDirection === 'asc'
                    ? a.numOccurrences - b.numOccurrences
                    : b.numOccurrences - a.numOccurrences;
            } else {
                return sortDirection === 'asc'
                    ? a.validity.localeCompare(b.validity)
                    : b.validity.localeCompare(a.validity);
            }
        });

        setFilteredFindings(results);
    }, [data.findings, validityFilter, typeFilter, sortField, sortDirection]);

    // Separate effect to reset pagination only when filters change
    useEffect(() => {
        setCurrentPage(1);
    }, [validityFilter, typeFilter, sortField, sortDirection]);

    // Calculate pagination
    const totalPages = Math.ceil(filteredFindings.length / ITEMS_PER_PAGE);
    const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
    const paginatedFindings = filteredFindings.slice(startIndex, startIndex + ITEMS_PER_PAGE);

    const handleSortChange = (field: 'secretType' | 'numOccurrences' | 'validity') => {
        if (sortField === field) {
            setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
        } else {
            setSortField(field);
            setSortDirection('asc');
        }
    };

    const handleViewOccurrences = (finding: Finding) => {
        // Navigate to the occurrences tab with fingerprint filter
        const url = chrome.runtime.getURL("options.html") +
            `?tab=findings&fingerprint=${finding.fingerprint}`;
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const currentTab = tabs[0];
            if (currentTab?.id !== undefined) {
                chrome.tabs.update(currentTab.id, { url });
            }
        });
    };

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
            } else if (finding.secretType === "LangSmith") {
                await langsmithValidityHelper(finding);
            } else if (finding.secretType === "Slack") {
                await slackValidityHelper(finding);
            } else if (finding.secretType === "PayPal OAuth") {
                await paypalOAuthValidityHelper(finding);
            }
        } catch (error) {
            console.error(`Validity check failed for ${finding.secretType}:`, error);
        }
    };

    const handleRecheckAll = async () => {
        setIsRechecking(true);
        setRecheckProgress({ current: 0, total: filteredFindings.length });

        // Create concurrent validation promises
        const validationPromises = filteredFindings.map(async (finding) => {
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

    const getValidityColorClass = (validity: ValidityStatus): string => {
        switch (validity) {
            case 'valid': return 'validity-valid';
            case 'invalid': return 'validity-invalid';
            case 'failed_to_check': return 'validity-failed';
            case 'unknown':
            default: return 'validity-unknown';
        }
    };

    const renderSortIcon = (field: 'secretType' | 'numOccurrences' | 'validity') => {
        if (sortField === field) {
            return sortDirection === 'asc' ? <ChevronUp size={16} /> : <ChevronDown size={16} />;
        }
        return <ChevronDown size={16} className="sort-icon-default" />;
    };

    return (
        <div className="tab-content">
            <h3>Findings</h3>

            {/* Search and Filter Controls */}
            <div className="filter-container">
                <div className="filter-row">
                    <div className="filter-item">
                        <label htmlFor="validity-filter">Validity Status:</label>
                        <select
                            id="validity-filter"
                            value={validityFilter}
                            onChange={(e) => setValidityFilter(e.target.value as ValidityStatus | 'all')}
                        >
                            <option value="all">All Statuses</option>
                            <option value="valid">Valid</option>
                            <option value="invalid">Invalid</option>
                            <option value="failed_to_check">Failed to Check</option>
                            <option value="unknown">Unknown</option>
                        </select>
                    </div>

                    <div className="filter-item">
                        <label htmlFor="type-filter">Secret Type:</label>
                        <select
                            id="type-filter"
                            value={typeFilter}
                            onChange={(e) => setTypeFilter(e.target.value)}
                        >
                            <option value="">All Types</option>
                            {uniqueSecretTypes.map((type, index) => (
                                <option key={index} value={type}>{type}</option>
                            ))}
                        </select>
                    </div>

                    {filteredFindings.length > 0 && (
                        <div className="filter-item">
                            <button
                                className="recheck-all-button tooltip"
                                onClick={handleRecheckAll}
                                disabled={isRechecking}
                                aria-label="Recheck all findings validity"
                                data-testid="recheck-all-button"
                            >
                                <RefreshCw size={16} className={`recheck-icon ${isRechecking ? 'spinning' : ''}`} />
                                <span>Recheck All</span>
                                <span className="tooltip-text">
                                    {isRechecking ? 'Rechecking validity...' : 'Recheck the validity of all findings'}
                                </span>
                            </button>
                        </div>
                    )}
                </div>

                {isRechecking && (
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
                )}
            </div>

            {/* Findings Table */}
            <div className="findings-table-container">
                {filteredFindings.length > 0 ? (
                    <>
                        <table className="findings-table">
                            <colgroup>
                                <col style={{ width: '40%' }} />
                                <col style={{ width: '30%' }} />
                                <col style={{ width: '20%' }} />
                                <col style={{ width: '10%' }} />
                            </colgroup>
                            <thead>
                                <tr>
                                    <th onClick={() => handleSortChange('secretType')}>
                                        <div className="sortable-header">
                                            <span>Type</span>
                                            {renderSortIcon('secretType')}
                                        </div>
                                    </th>
                                    <th onClick={() => handleSortChange('validity')}>
                                        <div className="sortable-header">
                                            <span>Validity</span>
                                            {renderSortIcon('validity')}
                                        </div>
                                    </th>
                                    <th onClick={() => handleSortChange('numOccurrences')}>
                                        <div className="sortable-header">
                                            <span>Occurrences</span>
                                            {renderSortIcon('numOccurrences')}
                                        </div>
                                    </th>
                                    <th className="actions-cell">{/* Empty header for actions column */}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {paginatedFindings.map((finding) => (
                                    <tr key={finding.fingerprint}>
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
                                        <td className="occurrence-td">{finding.numOccurrences}</td>
                                        <td className="actions-cell">
                                            <button
                                                className="view-button"
                                                onClick={() => handleViewOccurrences(finding)}
                                                title="View Occurrences"
                                            >
                                                <SquareArrowRight size={18} />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                        
                        {/* Pagination Controls */}
                        <div className="pagination-container">
                            <div className="pagination-info">
                                Showing {startIndex + 1}-{Math.min(startIndex + ITEMS_PER_PAGE, filteredFindings.length)} of {filteredFindings.length} findings
                            </div>
                            <div className="pagination-controls">
                                <button
                                    className="pagination-button"
                                    onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                                    disabled={currentPage === 1}
                                >
                                    <ChevronLeft size={16} />
                                    Previous
                                </button>
                                
                                <div className="pagination-pages">
                                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                                        <button
                                            key={page}
                                            className={`pagination-page ${currentPage === page ? 'active' : ''}`}
                                            onClick={() => setCurrentPage(page)}
                                        >
                                            {page}
                                        </button>
                                    ))}
                                </div>
                                
                                <button
                                    className="pagination-button"
                                    onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                                    disabled={currentPage === totalPages}
                                >
                                    Next
                                    <ChevronRight size={16} />
                                </button>
                            </div>
                        </div>
                    </>
                ) : (
                    <div className="empty-state">
                        <AlertTriangle size={48} />
                        <p>No findings match your filters.</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Findings;