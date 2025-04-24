import React, { useState, useEffect } from 'react';
import { Shield, Settings, Eye, Info } from 'lucide-react';
import '../../styles/variables.css';
import '../../styles/options.css';
import { SettingsTab } from '../components/SettingsTab';
import { Occurrences } from '../components/Occurrences';

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
            case 'occurrences':
                return <Occurrences filterFingerprint={filterFingerprint} />;
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
                    <img src="icons/leekr_icon_128x128.png" alt="Leekr Logo" className="logo" />
                    <h1>Leekr Settings</h1>
                </div>
            </header>

            <div className="options-content">
                <aside className="sidebar">
                    <nav>
                        <ul>
                            <li className={activeTab === 'general' ? 'active' : ''}>
                                <button onClick={() => setActiveTab('general')}>
                                    <Shield size={18} />
                                    <span>General</span>
                                </button>
                            </li>
                            <li className={activeTab === 'occurrences' ? 'active' : ''}>
                                <button onClick={() => setActiveTab('occurrences')}>
                                    <Eye size={18} />
                                    <span>Occurrences</span>
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