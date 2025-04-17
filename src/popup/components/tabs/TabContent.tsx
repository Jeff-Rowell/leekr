import React from 'react';
import FindingsTab from './findings/FindingsTab';
import PatternsTab from './patterns/PatternsTab';
import MoreTab from './more/MoreTab';

interface TabContentProps {
    activeTab: string;
}

const TabContent: React.FC<TabContentProps> = ({ activeTab }) => {
    switch (activeTab) {
        case 'Findings':
            return <FindingsTab />;
        case 'Patterns':
            return <PatternsTab />;
        case 'More':
            return <MoreTab />;
    }
};

export default TabContent;