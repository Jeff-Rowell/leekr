import { useState } from 'react';
import { useAppContext } from '../../popup/AppContext';

export const SettingsTab = () => {
    const { data: { suffixes, customSuffixesEnabled }, actions: { setSuffixes, setCustomSuffixesEnabled } } = useAppContext();
    const [newSuffix, setNewSuffix] = useState('');
    const [error, setError] = useState('');

    const handleCustomSuffixesToggle = async (e: React.MouseEvent) => {
        e.preventDefault();
        setCustomSuffixesEnabled(!customSuffixesEnabled);
    };

    const handleAddSuffix = async () => {
        if (!newSuffix) {
            setError('Please enter a suffix');
            return;
        }
        let normalizedSuffix = newSuffix;
        if (!normalizedSuffix.startsWith('.')) {
            normalizedSuffix = '.' + normalizedSuffix;
        }
        if (suffixes.some(s => s.value === normalizedSuffix)) {
            setError('This suffix already exists');
            return;
        }
        const updatedSuffixes = [
            ...suffixes,
            { id: crypto.randomUUID(), value: normalizedSuffix, isDefault: false }
        ];
        setSuffixes(updatedSuffixes);
        setNewSuffix('');
        setError('');
    };

    const handleDeleteSuffix = async (id: string) => {
        const updatedSuffixes = suffixes.filter(suffix => suffix.id !== id);
        setSuffixes(updatedSuffixes);
    };

    const handleResetToDefaults = async () => {
        const defaultSuffixes = suffixes.filter(suffix => suffix.isDefault);
        setSuffixes(defaultSuffixes);
    };

    return (
        <div className="tab-content">
            <div className="settings-section">
                <h3>Scanning</h3>
                <div className="setting-item">
                    <div className="setting-label">
                        <strong className="setting-label-strong">Enable Custom Scan Suffixes (Defaults: {suffixes.filter(suffix => suffix.isDefault).map(suffix => suffix.value).join(", ")})</strong>
                        <span className="setting-description">
                            Customize the file suffixes that Leekr scans
                        </span>
                    </div>
                    <div className="toggle-switch" onClick={handleCustomSuffixesToggle}>
                        <input
                            type="checkbox"
                            id="custom-suffixes-toggle"
                            checked={customSuffixesEnabled}
                            onChange={() => { }}
                        />
                        <span className="toggle-slider"></span>
                    </div>
                </div>

                {customSuffixesEnabled && (
                    <div className="setting-item suffix-form">
                        <div className="suffix-container">
                            <h4>File Suffixes</h4>
                            <div className="suffix-list">
                                {suffixes.map(suffix => (
                                    <div key={suffix.id} className="suffix-item">
                                        <span>{suffix.value}</span>
                                        {!suffix.isDefault && (
                                            <button
                                                className="suffix-delete-btn"
                                                onClick={() => handleDeleteSuffix(suffix.id)}
                                                title="Delete suffix"
                                            >
                                                ✕
                                            </button>
                                        )}
                                    </div>
                                ))}
                            </div>

                            <div className="suffix-form-row">
                                <div className="suffix-input-container">
                                    <input
                                        type="text"
                                        placeholder="Add new suffix (e.g. .tsx)"
                                        value={newSuffix}
                                        onChange={(e) => setNewSuffix(e.target.value)}
                                        className={error ? 'suffix-input error' : 'suffix-input'}
                                    />
                                    {error && <div className="suffix-error">{error}</div>}
                                </div>
                                <button
                                    className="suffix-add-btn"
                                    onClick={handleAddSuffix}
                                >
                                    Add
                                </button>
                            </div>

                            <div className="suffix-actions">
                                <button
                                    className="suffix-reset-btn"
                                    onClick={handleResetToDefaults}
                                >
                                    Reset to Defaults
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};