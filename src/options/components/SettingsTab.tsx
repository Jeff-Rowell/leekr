import { useState } from 'react';

export const SettingsTab = () => {
    const [notificationsEnabled, setNotificationsEnabled] = useState(true);
    const [autoScan, setAutoScan] = useState(true);

    return (
        <div className="tab-content">
            <h2>Settings</h2>

            <div className="settings-section">
                <h3>Notifications</h3>
                <div className="setting-item">
                    <label htmlFor="notifications-toggle">
                        Enable Notifications
                        <span className="setting-description">
                            Get notified when secrets are detected
                        </span>
                    </label>
                    <div className="toggle-switch">
                        <input
                            type="checkbox"
                            id="notifications-toggle"
                            checked={notificationsEnabled}
                            onChange={() => setNotificationsEnabled(!notificationsEnabled)}
                        />
                        <span className="toggle-slider"></span>
                    </div>
                </div>
            </div>

            <div className="settings-section">
                <h3>Scanning</h3>
                <div className="setting-item">
                    <label htmlFor="auto-scan-toggle">
                        Auto Scan
                        <span className="setting-description">
                            Automatically scan pages for secrets
                        </span>
                    </label>
                    <div className="toggle-switch">
                        <input
                            type="checkbox"
                            id="auto-scan-toggle"
                            checked={autoScan}
                            onChange={() => setAutoScan(!autoScan)}
                        />
                        <span className="toggle-slider"></span>
                    </div>
                </div>
            </div>
        </div>
    );
};