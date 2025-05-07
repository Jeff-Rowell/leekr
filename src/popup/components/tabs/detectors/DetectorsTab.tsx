import React from 'react';
import './style.css';
import { useAppContext } from '../../../AppContext';
import { SquareArrowRight } from 'lucide-react';
import { Pattern } from 'src/types/patterns.types';


const DetectorsTab: React.FC = () => {
    const { data: { findings, patterns } } = useAppContext();

    const getNumberOfFindings = (pattern: Pattern) => {
        return findings.filter(finding => finding.secretType === pattern.familyName).length;
    }

    const handleViewDetector = (pattern: Pattern) => {
        const url = chrome.runtime.getURL("options.html") +
            `?tab=detectors&familyname=${pattern.familyName}`;
        chrome.tabs.create({ url });
    }

    return (
        <section className="findings-tab">
            <div className="findings-section">
                <div className="findings-table-container">
                    <table className="findings-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Entropy</th>
                                <th>Findings</th>
                                <th>{/* Empty header for settings column */}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {Object.entries(patterns).map(([name, pattern], index) => (
                                <tr key={index}>
                                    <td className="findings-td">{name}</td>
                                    <td className="validity-cell">{pattern.entropy}</td>
                                    <td className="findings-td">{getNumberOfFindings(pattern)}</td>
                                    <td className="settings-cell">
                                        <button
                                            className="view-button"
                                            onClick={() => handleViewDetector(pattern)}
                                            title="View Detector"
                                        >
                                            <SquareArrowRight size={18} />
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </section>
    );
};

export default DetectorsTab;