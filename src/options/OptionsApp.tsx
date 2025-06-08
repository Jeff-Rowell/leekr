import React from 'react';
import { AppProvider } from '../popup/AppContext';
import '../styles/global.css';
import '../styles/options.css';
import '../styles/variables.css';
import Options from './pages/Options';

const OptionsApp: React.FC = () => {
    return (
        <AppProvider>
            <Options />
        </AppProvider>
    );
};

export default OptionsApp;
