import { AlertTriangle, ChevronDown, ChevronUp, Download, RotateCw, ShieldCheck, SquareArrowOutUpRight } from 'lucide-react';
import React, { useEffect, useState } from 'react';
import { useAppContext } from '../../popup/AppContext';
import { Finding } from '../../types/findings.types';
import { awsValidityHelper } from '../../utils/validators/aws/aws_access_keys/awsValidityHelper';
import { awsSessionValidityHelper } from '../../utils/validators/aws/aws_session_keys/awsValidityHelper';


export const Occurrences: React.FC<{ filterFingerprint?: string }> = ({ filterFingerprint }) => {
    const { data } = useAppContext();
    const [filteredFindings, setFilteredFindings] = useState<Finding[]>([]);
    const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
    const [expandedItems, setExpandedItems] = useState<Record<string, boolean>>({});

    useEffect(() => {
        if (filterFingerprint) {
            const filtered = data.findings.filter(occ => occ.fingerprint === filterFingerprint);
            setFilteredFindings(filtered);
            const finding = data.findings.find(f => f.fingerprint === filterFingerprint);
            if (finding) {
                setSelectedFinding(finding);
            }
        } else {
            setFilteredFindings(data.findings);
            setSelectedFinding(null);
        }
    }, [filterFingerprint, data.findings]);

    const handleValidityCheck = async (finding: Finding) => {
        if (finding.secretType === "AWS Access & Secret Keys") {
            awsValidityHelper(finding);
        } else if (finding.secretType === "AWS Session Keys") {
            awsSessionValidityHelper(finding)
        }
    };

    const toggleExpand = (fingerprint: string) => {
        setExpandedItems(prev => ({
            ...prev,
            [fingerprint]: !prev[fingerprint]
        }));
    };

    const downloadSourceContent = (content: string, filename: string, fingerprint: string) => {
        const safeFilename = `${fingerprint}-${filename.replace(/[/\\?%*:|"<>]/g, '_')}`;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = safeFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    return (
        <div className="tab-content">
            {selectedFinding && (
                <div className="selected-finding-header">
                    <h3>{selectedFinding.secretType}</h3>
                    <div className="finding-meta">
                        <span className={`validity-status validity-${selectedFinding.validity}`}>
                            {selectedFinding.validity.replace(/_/g, ' ')}

                            {selectedFinding.validatedAt && (
                                <div className="validity-info tooltip">
                                    <ShieldCheck size={16} />
                                    <span className="tooltip-text">
                                        Last Checked: {new Date(selectedFinding.validatedAt).toLocaleString()}
                                        <button
                                            className="recheck-button"
                                            onClick={() => handleValidityCheck(selectedFinding)}
                                            aria-label="Recheck validity"
                                        >
                                            <RotateCw size={14} />
                                        </button>
                                    </span>
                                </div>
                            )}
                        </span>
                        <span>{filteredFindings.length} occurrences</span>
                    </div>
                </div>
            )}

            <div className="occurrences-list">
                {filteredFindings.length > 0 ? (
                    filteredFindings.map((finding) => (
                        Array.from(finding.occurrences).map((occurrence) => (
                            <div key={occurrence.fingerprint} className="occurrence-item">
                                <div
                                    className="occurrence-header"
                                    onClick={() => toggleExpand(occurrence.fingerprint)}
                                >
                                    <div className="occurrence-info">
                                        <div className="occurrence-path">{occurrence.sourceContent.contentFilename}: Line {occurrence.sourceContent.contentStartLineNum + 5}</div>
                                        <button
                                            className="findings-source-download-btn"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                downloadSourceContent(
                                                    occurrence.sourceContent.content,
                                                    occurrence.sourceContent.contentFilename,
                                                    occurrence.fingerprint
                                                );
                                            }}
                                            title="Download Source Code"
                                            aria-label="Download Source Code"
                                        >
                                            <Download size={18} />
                                        </button>
                                    </div>
                                    <div className="occurrence-header-actions">
                                        {occurrence.url && (
                                            <a
                                                href={occurrence.url}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="occurrence-link"
                                                title="View JS Bundle"
                                                onClick={(e) => e.stopPropagation()}
                                            >
                                                <span className="link-text">View JS Bundle</span>
                                                <SquareArrowOutUpRight size={18} />
                                            </a>
                                        )}
                                        <button
                                            className="expand-toggle-btn"
                                            aria-label={expandedItems[occurrence.fingerprint] ? "Collapse code" : "Expand code"}
                                        >
                                            {expandedItems[occurrence.fingerprint] ?
                                                <ChevronUp size={18} /> :
                                                <ChevronDown size={18} />
                                            }
                                        </button>
                                    </div>
                                </div>
                                {expandedItems[occurrence.fingerprint] && (
                                    <div className="occurrence-context code-with-line-numbers">
                                        <pre>
                                            {occurrence.sourceContent.content.split('\n').map((line, index) => {
                                                const currentLineNum = occurrence.sourceContent.contentStartLineNum + index;
                                                const highlightLine = occurrence.sourceContent.exactMatchNumbers &&
                                                    occurrence.sourceContent.exactMatchNumbers.includes(currentLineNum + 1);

                                                if (currentLineNum >= occurrence.sourceContent.contentStartLineNum &&
                                                    currentLineNum <= occurrence.sourceContent.contentEndLineNum) {
                                                    return (
                                                        <div
                                                            key={index}
                                                            className={`code-line ${highlightLine ? 'highlighted-line' : ''}`}
                                                        >
                                                            <span className="line-number">{currentLineNum + 1}</span>
                                                            <span className="line-content">{occurrence.sourceContent.content.split('\n')[currentLineNum]}</span>
                                                        </div>
                                                    );
                                                }
                                                return null;
                                            })}
                                        </pre>
                                    </div>
                                )}
                            </div>
                        ))
                    ))
                ) : (
                    <div className="empty-state">
                        <AlertTriangle size={48} />
                        <p>No occurrences found.</p>
                    </div>
                )}
            </div>
        </div>
    );
};