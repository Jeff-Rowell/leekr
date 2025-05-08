import { useState } from 'react';

export const SettingsTab = () => {
    const [notificationsEnabled, setNotificationsEnabled] = useState(true);
    const [customSuffixesEnabled, setCustomSuffixesEnabled] = useState(false);

    const handleToggleClick = (setter: React.Dispatch<React.SetStateAction<boolean>>, currentValue: boolean) => (e: React.MouseEvent) => {
        e.preventDefault();
        setter(!currentValue);
    };

    return (
        <div className="tab-content">
            <div className="settings-section">
                <h3>Notifications</h3>
                <div className="setting-item">
                    <div className="setting-label">
                        <strong className="setting-label-strong">Enable Notifications</strong>
                        <span className="setting-description">
                            Get pop-up notifications when secrets are found
                        </span>
                    </div>
                    <div className="toggle-switch" onClick={handleToggleClick(setNotificationsEnabled, notificationsEnabled)}>
                        <input
                            type="checkbox"
                            id="notifications-toggle"
                            checked={notificationsEnabled}
                            onChange={() => { }}
                        />
                        <span className="toggle-slider"></span>
                    </div>
                </div>
            </div>

            <div className="settings-section">
                <h3>Scanning</h3>
                <div className="setting-item">
                    <div className="setting-label">
                        <strong className="setting-label-strong">Enable Custom Scan Suffixes</strong>
                        <span className="setting-description">
                            Customize the file suffixes that Leekr scans (Default: .js, .mjs, .cjs)
                        </span>
                    </div>
                    <div className="toggle-switch" onClick={handleToggleClick(setCustomSuffixesEnabled, customSuffixesEnabled)}>
                        <input
                            type="checkbox"
                            id="custom-suffixes-toggle"
                            checked={customSuffixesEnabled}
                            onChange={() => { }}
                        />
                        <span className="toggle-slider"></span>
                    </div>
                </div>
            </div>
        </div>
    );
};