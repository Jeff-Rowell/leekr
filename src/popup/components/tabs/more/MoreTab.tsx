import { Power, Trash2 } from 'lucide-react';
import React from 'react';
import { useAppContext } from '../../../AppContext';
import './style.css';

const MoreTab: React.FC = () => {
    const { data: { isExtensionEnabled }, actions: { clearAllFindings, toggleExtension } } = useAppContext();

    const handleClearFindings = () => {
        if (isExtensionEnabled) {
            if (window.confirm('Are you sure you want to clear all findings? This action cannot be undone.')) {
                clearAllFindings();
            }
        }
    };

    const handleToggle = () => {
        toggleExtension(!isExtensionEnabled);
    };

    return (
        <section className="more-tab leekr-extension-toggle">
            <div className="more-tab-section leekr-extension-toggle">
                <div className="more-tab-card">
                    <div className="more-tab-card-content">
                        <div className="more-tab-card-text">
                            <h4 className="more-tab-card-title">Delete All Findings</h4>
                            <p className="more-tab-card-description">
                                Permanently deletes findings from storage. This cannot be undone.
                            </p>
                        </div>
                    </div>
                    <div className="more-tab-card-icon danger-button">
                        <Trash2 size={20} onClick={handleClearFindings} />
                    </div>
                </div>
                <div className="more-tab-card leekr-extension-toggle">
                    <div className="more-tab-card-content leekr-extension-toggle">
                        <div className="more-tab-card-text leekr-extension-toggle">
                            <h4 className="leekr-extension-toggle more-tab-card-title">{isExtensionEnabled ? 'Disable Extension' : 'Enable Extension'}</h4>
                            <p className="leekr-extension-toggle more-tab-card-description">
                                Enable or disable Leekr from scanning.
                            </p>
                        </div>
                    </div>
                    <div className={`leekr-extension-toggle toggle-button ${isExtensionEnabled ? 'disabled' : 'enabled'}`} >
                        <Power size={20} onClick={handleToggle} className="leekr-extension-toggle" />
                        <span className="toggle-status leekr-extension-toggle" onClick={handleToggle}>{isExtensionEnabled ? 'Turn Off' : 'Turn On'}</span>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default MoreTab;