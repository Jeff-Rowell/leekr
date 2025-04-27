import React, { useState, useEffect } from 'react';
import { AlertTriangle } from 'lucide-react';
import { Finding } from '../../types/findings.types';
import { useAppContext } from '../../popup/AppContext';

// Types for occurrences
interface Occurrence {
    id: string;
    filePath: string;
    lineNumber: number;
    context: string;
    url?: string;
    findingFingerprint: string;
}


export const Occurrences: React.FC<{ filterFingerprint?: string }> = ({ filterFingerprint }) => {
    const { data } = useAppContext();
    const [occurrences, setOccurrences] = useState<Occurrence[]>([]);
    const [filteredOccurrences, setFilteredOccurrences] = useState<Occurrence[]>([]);
    const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

    useEffect(() => {
        // This would normally be loaded from storage or an API
        // For demo purposes, we'll create some sample data
        const loadOccurrences = async () => {
            // In a real implementation, this would load from chrome storage or your backend
            const sampleOccurrences: Occurrence[] = [];

            // Create some sample occurrences for each finding
            data.findings.forEach(finding => {
                for (let i = 0; i < finding.numOccurrences; i++) {
                    sampleOccurrences.push({
                        id: `${finding.fingerprint}-${i}`,
                        filePath: `src/components/Example${i}.tsx`,
                        lineNumber: Math.floor(Math.random() * 100) + 1,
                        context: `const apiKey = "***********";`,
                        findingFingerprint: finding.fingerprint
                    });
                }
            });

            setOccurrences(sampleOccurrences);
        };

        loadOccurrences();
    }, [data.findings]);

    // Filter occurrences when fingerprint changes
    useEffect(() => {
        if (filterFingerprint) {
            const filtered = occurrences.filter(occ => occ.findingFingerprint === filterFingerprint);
            setFilteredOccurrences(filtered);

            // Set the selected finding
            const finding = data.findings.find(f => f.fingerprint === filterFingerprint);
            if (finding) {
                setSelectedFinding(finding);
            }
        } else {
            setFilteredOccurrences(occurrences);
            setSelectedFinding(null);
        }
    }, [filterFingerprint, occurrences, data.findings]);

    return (
        <div className="tab-content">
            {selectedFinding && (
                <div className="selected-finding-header">
                    <h2>Occurrences for {selectedFinding.secretType}</h2>
                    <div className="finding-meta">
                        <span className={`validity-badge ${selectedFinding.validity}`}>
                            {selectedFinding.validity.replace(/_/g, ' ')}
                        </span>
                        <span>{filteredOccurrences.length} occurrences</span>
                    </div>
                </div>
            )}

            <div className="occurrences-list">
                {filteredOccurrences.length > 0 ? (
                    filteredOccurrences.map((occurrence) => (
                        <div key={occurrence.id} className="occurrence-item">
                            <div className="occurrence-path">{occurrence.filePath}</div>
                            <div className="occurrence-line">Line {occurrence.lineNumber}</div>
                            <div className="occurrence-context">
                                <pre>{occurrence.context}</pre>
                            </div>
                            {occurrence.url && (
                                <a href={occurrence.url} target="_blank" rel="noopener noreferrer"
                                    className="occurrence-link">Open File</a>
                            )}
                        </div>
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