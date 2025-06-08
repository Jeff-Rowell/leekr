import React from 'react';
import '../styles/global.css';
import '../styles/index.css';
import '../styles/variables.css';
import { AppProvider } from './AppContext';
import Layout from './pages/Layout';

const App: React.FC = () => {
    return (
        <AppProvider>
            <Layout />
        </AppProvider>
    );
};

export default App;
