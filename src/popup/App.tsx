import React from 'react';
import Layout from './pages/Layout';
import '../styles/index.css';
import '../styles/global.css';
import '../styles/variables.css';
import { AppProvider } from './AppContext';

const App: React.FC = () => {
    return (
        <AppProvider>
            <Layout />
        </AppProvider>
    );
};

export default App;
