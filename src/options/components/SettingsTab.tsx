import { useState } from 'react';

export const SettingsTab = () => {
    const [notificationsEnabled, setNotificationsEnabled] = useState(true);
    const [autoScan, setAutoScan] = useState(true);

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
                        Enable Notifications
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
                        Auto Scan
                        <span className="setting-description">
                            Automatically scan pages for secrets
                        </span>
                    </div>
                    <div className="toggle-switch" onClick={handleToggleClick(setAutoScan, autoScan)}>
                        <input
                            type="checkbox"
                            id="auto-scan-toggle"
                            checked={autoScan}
                            onChange={() => { }}
                        />
                        <span className="toggle-slider"></span>
                    </div>
                </div>
            </div>
        </div>
    );
};