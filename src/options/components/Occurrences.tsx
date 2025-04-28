import React, { useState, useEffect } from 'react';
import { AlertTriangle, SquareArrowOutUpRight } from 'lucide-react';
import { Finding, Occurrence } from '../../types/findings.types';
import { useAppContext } from '../../popup/AppContext';


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

    return (
        <div className="tab-content">
            {selectedFinding && (
                <div className="selected-finding-header">
                    <h2>{selectedFinding.secretType}</h2>
                    <div className="finding-meta">
                        <span className={`validity-badge ${selectedFinding.validity}`}>
                            {selectedFinding.validity.replace(/_/g, ' ')}
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
                                <div className="occurrence-header">
                                    <div className="occurrence-info">
                                        <div className="occurrence-path">{occurrence.filePath}</div>
                                        {/* <div className="occurrence-line">Line 69</div> TODO: reverse the bundle and find the line number */}
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