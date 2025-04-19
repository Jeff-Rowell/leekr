
import { X } from 'lucide-react';
import './style.css';

interface ModalHeaderProps {
    title?: string;
    onClose: () => void;
}

export default function ModalHeader({ title, onClose }: ModalHeaderProps) {
    return (
        <div className="modal-header">
            <h1>{title}</h1>
            <button
                onClick={onClose}
                className="transition-colors duration-200"
                aria-label="Close modal"
            >
                <X size={18} />
            </button>
        </div>
    );
}