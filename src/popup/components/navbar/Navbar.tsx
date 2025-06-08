import React from 'react';
import { useAppContext } from '../../AppContext';
import './style.css';

const Navbar: React.FC = () => {
    const { data, actions } = useAppContext();

    const handleTabClick = (tab: string) => {
        actions.setActiveTab(tab);
    };

    const tabs = ['Findings', 'Detectors', 'More'];

    return (
        <div className="navbar">
            <div className="tab-container">
                {tabs.map((tab) => (
                    <button
                        key={tab}
                        className={`tab-button ${data.activeTab === tab ? 'active' : ''}`}
                        onClick={() => handleTabClick(tab)}
                        disabled={!data.isExtensionEnabled}
                    >
                        {tab}
                    </button>
                ))}
            </div>
        </div>
    );
};

export default Navbar;