import React from 'react';
import { Trash2, Power } from 'lucide-react';
import { useAppContext } from '../../../AppContext';
import './style.css';

const MoreTab: React.FC = () => {
    const { data: { isExtensionEnabled }, actions: { clearAllFindings, toggleExtension } } = useAppContext();

    const handleClearFindings = () => {
        if (window.confirm('Are you sure you want to clear all findings? This action cannot be undone.')) {
            clearAllFindings();
        }
    };

    return (
        <section className="more-tab">
            <div className="more-tab-section">
                <div className="more-tab-card">
                    <div className="more-tab-card-content">
                        <div className="more-tab-card-text">
                            <h4 className="more-tab-card-title">Delete All Findings</h4>
                            <p className="more-tab-card-description">
                                Permanently deletes all findings from storage. This action cannot be undone.
                            </p>
                        </div>
                    </div>
                    <div className="more-tab-card-icon danger-button">
                        <Trash2 size={20} onClick={handleClearFindings} />
                    </div>
                </div>
                <div className="more-tab-card">
                    <div className="more-tab-card-content">
                        <div className="more-tab-card-text">
                            <h4 className="more-tab-card-title">{isExtensionEnabled ? 'Disable Extension' : 'Enable Extension'}</h4>
                            <p className="more-tab-card-description">
                                Enable or disable Leekr from scanning.
                            </p>
                        </div>
                    </div>
                    <div className={`toggle-button ${isExtensionEnabled ? 'disabled' : 'enabled'}`} >
                        <Power size={20} onClick={toggleExtension} />
                        <span className="toggle-status" onClick={toggleExtension}>{isExtensionEnabled ? 'Turn Off' : 'Turn On'}</span>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default MoreTab;