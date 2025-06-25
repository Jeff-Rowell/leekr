import {
    AlertTriangle,
    ChevronDown,
    ChevronUp,
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
        // Reset to first page when filters change
        setCurrentPage(1);
    }, [data.findings, validityFilter, typeFilter, sortField, sortDirection]);

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
        if (finding.secretType === "AWS Access & Secret Keys") {
            awsValidityHelper(finding);
        } else if (finding.secretType === "AWS Session Keys") {
            awsSessionValidityHelper(finding);
        } else if (finding.secretType === "Anthropic AI") {
            anthropicValidityHelper(finding);
        } else if (finding.secretType === "OpenAI") {
            openaiValidityHelper(finding);
        } else if (finding.secretType === "Gemini") {
            geminiValidityHelper(finding);
        } else if (finding.secretType === "Hugging Face") {
            huggingfaceValidityHelper(finding);
        }
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
                </div>
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
                        {/* Pagination controls remain the same */}
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