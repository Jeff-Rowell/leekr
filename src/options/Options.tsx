import React from 'react';
import { createRoot } from 'react-dom/client';

const Options: React.FC = () => {
    return (
        <div>
            <h1>Extension Options</h1>
        </div>
    );
};

const container = document.getElementById('root');
if (!container) throw new Error('Root element not found');
const root = createRoot(container);
root.render(<Options />);