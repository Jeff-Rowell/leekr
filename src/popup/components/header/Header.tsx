import React, { useState, useRef, useEffect } from 'react';
import { Download } from 'lucide-react';
import { useAppContext } from '../../AppContext';
import LeekrIcon from '../../../../public/icons/leekr_icon_128x128.png';
import LeekrFont from '../../../assets/leekr-font.svg';
import ModalHeader from '../../../components/ui/Modalheader';
import { Occurrence } from '../../../types/findings.types';
import './style.css';

const Header: React.FC = () => {
    const { data: { findings } } = useAppContext();
    const [showDownloadOptions, setShowDownloadOptions] = useState<boolean>(false);
    const [redactSecrets, setRedactSecrets] = useState<boolean>(true);
    const downloadOptionsRef = useRef<HTMLDivElement>(null);
    const downloadButtonRef = useRef<HTMLButtonElement>(null);

    const closeModal = () => {
        setShowDownloadOptions(false);
    };

    const downloadData = (format: 'csv' | 'json') => {
        let content: string;
        let filename: string;
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

        if (format === 'csv') {
            const findingFields = ['secretType', 'validity', 'validatedAt', 'fingerprint'];
            const occurrenceFieldsSet = new Set<string>();
            findings.forEach(finding => {
                Array.from(finding.occurrences).forEach(occurrence => {
                    Object.keys(occurrence).forEach(key => {
                        if (key !== 'secretValue') {
                            occurrenceFieldsSet.add(`occurrence.${key}`);
                        }
                    });
                });
            });

            let headers;
            if (redactSecrets) {
                headers = [
                    ...findingFields,
                    ...Array.from(occurrenceFieldsSet)
                ];
            } else {
                headers = [
                    ...findingFields,
                    'secretValue',
                    ...Array.from(occurrenceFieldsSet)
                ];
            }

            const csvRows = [headers.join(',')];
            findings.forEach(finding => {
                Array.from(finding.occurrences).forEach(occurrence => {
                    const row: string[] = [];
                    headers.forEach(header => {
                        if (header === 'secretType') {
                            row.push(finding.secretType || '');
                        } else if (header === 'validity') {
                            row.push(finding.validity || '');
                        } else if (header === 'validatedAt') {
                            row.push(finding.validatedAt || '');
                        } else if (header === 'fingerprint') {
                            row.push(finding.fingerprint || '');
                        } else if (!redactSecrets && header === 'secretValue') {
                            row.push(redactSecrets ? '********' : `"${JSON.stringify(finding.secretValue).replace(/"/g, "'")}"`);
                        } else if (header.startsWith('occurrence.')) {
                            const occField = header.replace('occurrence.', '');
                            let value: string = "";
                            if (occField in occurrence && occField !== 'secretValue') {
                                const fieldValue = (occurrence as any)[occField];
                                value = fieldValue !== undefined && fieldValue !== null ? String(fieldValue) : '';
                            }
                            row.push(value);
                        }
                    });
                    csvRows.push(row.join(','));
                });
            });
            csvRows[0] = csvRows[0].replace(/occurrence\./g, "");
            content = csvRows.join('\n');
            filename = `leekr-findings-${timestamp}.csv`;
        } else {
            const jsonData = findings.map(finding => {
                const modifiedFinding = {
                    ...finding,
                    secretValue: redactSecrets ? '********' : finding.secretValue,
                    occurrences: Array.from(finding.occurrences).map(occurrence => ({
                        ...occurrence,
                        secretValue: redactSecrets ? '********' : occurrence.secretValue
                    }))
                };
                return modifiedFinding;
            });

            content = JSON.stringify(jsonData, null, 2);
            filename = `leekr-findings-${timestamp}.json`;
        }

        const blob = new Blob([content], { type: format === 'csv' ? 'text/csv' : 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        setShowDownloadOptions(false);
    };

    const toggleDownloadOptions = () => {
        setShowDownloadOptions(!showDownloadOptions);
    };

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (
                showDownloadOptions &&
                downloadOptionsRef.current &&
                downloadButtonRef.current &&
                !downloadOptionsRef.current.contains(event.target as Node) &&
                !downloadButtonRef.current.contains(event.target as Node)
            ) {
                setShowDownloadOptions(false);
            }
        };

        if (showDownloadOptions) {
            document.addEventListener('mousedown', handleClickOutside);
        }

        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [showDownloadOptions]);

    return (
        <header className="flex items-center mr-3 p-2 leekr-header">
            <img
                src={LeekrIcon}
                alt="Leekr"
            />
            <div className="flex flex-col items-center">
                <LeekrFont className="h-10 header-svg" />
                <div className="flex flex-col items-center relative">
                    <div className="flex items-center">
                        {findings.length > 0 && (
                            <h1 className="h1-text-center">
                                {findings.length} {findings.length === 1 ? 'Secret' : 'Secrets'} Detected
                            </h1>
                        )}
                        {findings.length > 0 && (
                            <button type="button" className="download-button" onClick={toggleDownloadOptions} ref={downloadButtonRef}>
                                <Download className="download-component" size={18} />
                            </button>
                        )}
                    </div>

                    {showDownloadOptions && (
                        <div className="download-options absolute top-full mt-1 shadow-md rounded border p-2 z-10" ref={downloadOptionsRef}>
                            <ModalHeader title="Findings Download" onClose={closeModal} />
                            <div className="format-buttons">
                                <button onClick={() => downloadData('csv')}>CSV</button>
                                <button onClick={() => downloadData('json')}>JSON</button>
                            </div>
                            <div className="redact-option">
                                <input
                                    type="checkbox"
                                    id="redact-secrets"
                                    checked={redactSecrets}
                                    onChange={() => setRedactSecrets(!redactSecrets)}
                                />
                                <label htmlFor="redact-secrets">Redact Secret Values</label>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </header >
    );
};

export default Header;
