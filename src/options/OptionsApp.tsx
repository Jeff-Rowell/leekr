import React from 'react';
import Options from './pages/Options';
import '../styles/options.css';
import '../styles/variables.css';
import '../styles/global.css';
import { AppProvider } from '../popup/AppContext';

const OptionsApp: React.FC = () => {
    return (
        <AppProvider>
            <Options />
        </AppProvider>
    );
};

export default OptionsApp;
