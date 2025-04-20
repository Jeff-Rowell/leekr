import React from 'react';
import './style.css';
import { useAppContext } from '../../AppContext';

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
                    >
                        {tab}
                    </button>
                ))}
            </div>
        </div>
    );
};

export default Navbar;