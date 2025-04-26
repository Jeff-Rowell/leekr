import React from 'react';
import './style.css';
import { useAppContext } from '../../AppContext';

const Navbar: React.FC = () => {
    const { state, dispatch } = useAppContext();

    const handleTabClick = (tab: string) => {
        dispatch({ type: 'SET_ACTIVE_TAB', tab: tab });
    };

    const tabs = ['Findings', 'Detectors', 'More'];

    return (
        <div className="navbar">
            <div className="tab-container">
                {tabs.map((tab) => (
                    <button
                        key={tab}
                        className={`tab-button ${state.activeTab === tab ? 'active' : ''}`}
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