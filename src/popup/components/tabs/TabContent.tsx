import React from 'react';
import DetectorsTab from './detectors/DetectorsTab';
import FindingsTab from './findings/FindingsTab';
import MoreTab from './more/MoreTab';

interface TabContentProps {
    activeTab: string;
}

const TabContent: React.FC<TabContentProps> = ({ activeTab }) => {
    switch (activeTab) {
        case 'Findings':
            return <FindingsTab />;
        case 'Detectors':
            return <DetectorsTab />;
        case 'More':
            return <MoreTab />;
    }
};

export default TabContent;