import React, { useState, useEffect } from 'react';
import { Shield, Settings, Eye, Info, Boxes } from 'lucide-react';
import LeekrFont from '../../assets/leekr-font.svg';
import SettingsFont from '../../assets/settings-font.svg';
import { SettingsTab } from '../components/SettingsTab';
import { Occurrences } from '../components/Occurrences';
import { Findings } from '../components/Findings';

// Tab components
const General = () => <div className="tab-content">General</div>;
const Patterns = () => <div className="tab-content">Detection Patterns</div>;
const AboutTab = () => <div className="tab-content">About Leekr</div>;

// Main Options component
const Options: React.FC = () => {
    const [activeTab, setActiveTab] = useState('general');
    const [filterFingerprint, setFilterFingerprint] = useState<string | undefined>(undefined);

    useEffect(() => {
        // Parse URL parameters to get the active tab and filters
        const searchParams = new URLSearchParams(window.location.search);
        const tabParam = searchParams.get('tab');
        const fingerprintParam = searchParams.get('fingerprint');

        if (tabParam) {
            setActiveTab(tabParam);
        }

        if (fingerprintParam) {
            setFilterFingerprint(fingerprintParam);
        }
    }, []);

    const renderTabContent = () => {
        switch (activeTab) {
            case 'general':
                return <General />;
            case 'patterns':
                return <Patterns />;
            case 'findings':
                // If we have a fingerprint, show occurrences for that fingerprint
                // Otherwise show the findings tab
                return filterFingerprint ?
                    <Occurrences filterFingerprint={filterFingerprint} /> :
                    <Findings />;
            case 'settings':
                return <SettingsTab />;
            case 'about':
                return <AboutTab />;
            default:
                return <General />;
        }
    };

    return (
        <div className="options-container">
            <header className="options-header">
                <div className="logo-container">
                    <img src="icons/leekr_head_icon_trimmed_128x128.png" alt="Leekr Logo" className="logo" />
                    <LeekrFont className="h-10 leekr-svg" />
                    <SettingsFont className="h-10 settings-svg" />
                </div>
            </header>

            <div className="options-content">
                <aside className="sidebar">
                    <nav>
                        <ul>
                            <li className={activeTab === 'general' ? 'active' : ''}>
                                <button onClick={() => setActiveTab('general')}>
                                    <Boxes size={18} />
                                    <span>General</span>
                                </button>
                            </li>
                            <li className={activeTab === 'findings' ? 'active' : ''}>
                                <button onClick={() => {
                                    setActiveTab('findings');
                                    setFilterFingerprint(undefined); // Clear any filter when clicking the Findings tab
                                }}>
                                    <Eye size={18} />
                                    <span>Findings</span>
                                </button>
                            </li>
                            <li className={activeTab === 'patterns' ? 'active' : ''}>
                                <button onClick={() => setActiveTab('patterns')}>
                                    <Shield size={18} />
                                    <span>Patterns</span>
                                </button>
                            </li>
                            <li className={activeTab === 'settings' ? 'active' : ''}>
                                <button onClick={() => setActiveTab('settings')}>
                                    <Settings size={18} />
                                    <span>Settings</span>
                                </button>
                            </li>
                            <li className={activeTab === 'about' ? 'active' : ''}>
                                <button onClick={() => setActiveTab('about')}>
                                    <Info size={18} />
                                    <span>About</span>
                                </button>
                            </li>
                        </ul>
                    </nav>
                </aside>

                <main className="main-content">
                    {renderTabContent()}
                </main>
            </div>
        </div>
    );
};

export default Options;