import React from 'react';
import './style.css';
import { useAppContext } from '../../../AppContext';
import { RotateCw } from 'lucide-react';
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger
} from "../../../../components/ui/tooltip";
import { Finding, ValidityStatus } from 'src/types/findings.types';
import { awsValidityHelper } from '../../utils/awsValidityHelper';

const FindingsTab: React.FC = () => {
    const { data: { findings } } = useAppContext();

    const handleValidityCheck = async (finding: Finding) => {
        console.log("validating finding =", finding)
        if (finding.secretType === "AWS Access & Secret Keys") {
            awsValidityHelper(finding);
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
            case 'no_checker': return 'validity-no-checker';
            case 'unknown':
            default: return 'validity-unknown';
        }
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
                                                <TooltipProvider>
                                                    <Tooltip>
                                                        <TooltipTrigger asChild>
                                                            <div className="validity-info">
                                                                <span className="info-icon">i</span>
                                                            </div>
                                                        </TooltipTrigger>
                                                        <TooltipContent>
                                                            Last Checked: {new Date(finding.validatedAt).toLocaleString()}
                                                        </TooltipContent>
                                                    </Tooltip>
                                                </TooltipProvider>
                                            )}

                                            <button
                                                className="recheck-button"
                                                onClick={() => handleValidityCheck(finding)}
                                                aria-label="Recheck validity"
                                            >
                                                <RotateCw size={14} />
                                            </button>
                                        </div>
                                    </td>
                                    <td className="findings-td">{finding.numOccurrences}</td>
                                    {/* <td className="file-path"><a target="_blank" href={finding.url}>{finding.filePath}</a></td> */}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </section>
    );
};

export default FindingsTab;