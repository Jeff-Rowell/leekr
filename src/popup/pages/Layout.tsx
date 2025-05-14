import React from 'react';
import Header from '../components/header/Header';
import Navbar from '../components/navbar/Navbar';
import TabContent from '../components/tabs/TabContent';
import { useAppContext } from '../AppContext';

const Layout: React.FC = () => {
    const { data } = useAppContext();

    return (
        <div className={"content" + (data.isExtensionEnabled ? "" : "-disabled")}>
            <Header />
            <Navbar />
            <TabContent activeTab={data.activeTab} />
        </div>
    );
};

export default Layout;