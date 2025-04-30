import React, { useState, useEffect } from 'react';
import { AlertTriangle, SquareArrowOutUpRight, ShieldCheck, RotateCw } from 'lucide-react';
import { Finding } from '../../types/findings.types';
import { useAppContext } from '../../popup/AppContext';
import { awsValidityHelper } from '../../popup/components/utils/awsValidityHelper';


export const Occurrences: React.FC<{ filterFingerprint?: string }> = ({ filterFingerprint }) => {
    const { data } = useAppContext();
    const [filteredFindings, setFilteredFindings] = useState<Finding[]>([]);
    const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

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
        }
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
                            occurrence.sourceContent && occurrence.sourceContent.contentStartLineNum > 0 ? (
                                <div key={occurrence.fingerprint} className="occurrence-item">
                                    <div className="occurrence-header">
                                        <div className="occurrence-info">
                                            <div className="occurrence-path">{occurrence.sourceContent.contentFilename}: Line {occurrence.sourceContent.contentStartLineNum + 5}</div>
                                        </div>
                                        {occurrence.url && (
                                            <a href={occurrence.url} target="_blank" rel="noopener noreferrer"
                                                className="occurrence-link" title="View JS Bundle">
                                                View JS Bundle
                                                <SquareArrowOutUpRight size={18} />
                                            </a>
                                        )}
                                    </div>
                                    <div className="occurrence-context code-with-line-numbers">
                                        <pre>
                                            {occurrence.sourceContent.content.split('\n').map((line, index) => {
                                                const currentLineNum = occurrence.sourceContent.contentStartLineNum + index;
                                                if (currentLineNum >= occurrence.sourceContent.contentStartLineNum &&
                                                    currentLineNum <= occurrence.sourceContent.contentEndLineNum) {
                                                    return (
                                                        <div key={index} className="code-line">
                                                            <span className="line-number">{currentLineNum + 1}</span>
                                                            <span className="line-content">{occurrence.sourceContent.content.split('\n')[currentLineNum]}</span>
                                                        </div>
                                                    );
                                                }
                                                return null;
                                            })}
                                        </pre>
                                    </div>
                                </div>
                            ) : (
                                <div key={occurrence.fingerprint} className="occurrence-item">
                                    <div className="occurrence-header">
                                        <div className="occurrence-info">
                                            <div className="occurrence-path">{occurrence.filePath}</div>
                                        </div>
                                        {occurrence.url && (
                                            <a href={occurrence.url} target="_blank" rel="noopener noreferrer"
                                                className="occurrence-link" title="View File">
                                                <SquareArrowOutUpRight size={18} />
                                            </a>
                                        )}
                                    </div>
                                    <div className="occurrence-context">
                                        <pre>{JSON.stringify(occurrence.secretValue)}</pre>
                                    </div>
                                </div>
                            )
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