import React, { useState, useEffect } from 'react';
import {
    ChevronDown,
    ChevronUp,
    AlertTriangle,
    Search,
    SquareArrowRight
} from 'lucide-react';
import { Pattern } from '../../types/patterns.types';
import { useAppContext } from '../../popup/AppContext';

// Pagination constants
const ITEMS_PER_PAGE = 10;

export const Patterns: React.FC = () => {
    const { data } = useAppContext();
    const [currentPage, setCurrentPage] = useState(1);
    const [filteredPatterns, setFilteredPatterns] = useState<Pattern[]>([]);
    const [sortField, setSortField] = useState<'name' | 'pattern' | 'entropy'>('name');
    const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
    const [searchQuery, setSearchQuery] = useState<string>('');

    useEffect(() => {
        let patterns = [...data.patterns];
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            patterns = patterns.filter(pattern =>
                pattern.name.toLowerCase().includes(query)
            );
        }

        patterns.sort((a, b) => {
            if (sortField === 'name') {
                return sortDirection === 'asc'
                    ? a.name.localeCompare(b.name)
                    : b.name.localeCompare(a.name);
            } else if (sortField === 'pattern') {
                return sortDirection === 'asc'
                    ? a.pattern.source.localeCompare(b.pattern.source)
                    : b.pattern.source.localeCompare(a.pattern.source);
            } else {
                return sortDirection === 'asc'
                    ? a.entropy - b.entropy
                    : b.entropy - a.entropy;
            }
        });

        setFilteredPatterns(patterns);
        setCurrentPage(1);
    }, [data.patterns, sortDirection, searchQuery]);

    const totalPages = Math.ceil(filteredPatterns.length / ITEMS_PER_PAGE);
    const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
    const paginatedPatterns = filteredPatterns.slice(startIndex, startIndex + ITEMS_PER_PAGE);

    const handleSortChange = (field: 'name' | 'pattern' | 'entropy') => {
        if (sortField === field) {
            setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
        } else {
            setSortField(field);
            setSortDirection('asc');
        }
    };

    const renderSortIcon = (field: 'name' | 'pattern' | 'entropy') => {
        if (sortField === field) {
            return sortDirection === 'asc' ? <ChevronUp size={16} /> : <ChevronDown size={16} />;
        }
        return <ChevronDown size={16} className="sort-icon-default" />;
    };

    return (
        <div className="tab-content">
            <h3>Patterns</h3>
            <div className="filter-container">
                <div className="filter-row">
                    <div className="filter-item">
                        <div className="search-box">
                            <Search size={20} />
                            <input
                                type="text"
                                placeholder="Search patterns..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                            />
                        </div>
                    </div>
                </div>
            </div>

            <div className="patterns-table-container">
                {filteredPatterns.length > 0 ? (
                    <>
                        <table className="patterns-table">
                            <colgroup>
                                <col style={{ width: '20%' }} />
                                <col style={{ width: '65%' }} />
                                <col style={{ width: '10%' }} />
                                <col style={{ width: '5%' }} />
                            </colgroup>
                            <thead>
                                <tr>
                                    <th className="patterns-th" onClick={() => handleSortChange('name')}>
                                        <div className="sortable-header">
                                            <span>Name</span>
                                            {renderSortIcon('name')}
                                        </div>
                                    </th>
                                    <th className="patterns-th" onClick={() => handleSortChange('pattern')}>
                                        <div className="sortable-header">
                                            <span>Pattern</span>
                                            {renderSortIcon('pattern')}
                                        </div>
                                    </th>
                                    <th className="patterns-th" onClick={() => handleSortChange('entropy')}>
                                        <div className="sortable-header">
                                            <span>Entropy</span>
                                            {renderSortIcon('entropy')}
                                        </div>
                                    </th>
                                    <th className="actions-cell">{/* Empty header for actions column */}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {paginatedPatterns.map((pattern, index) => (
                                    <tr key={index}>
                                        <td className="patterns-td">{pattern.name}</td>
                                        <td className="patterns-td"><pre className='pattern-pre'>{pattern.global ? "/" + pattern.pattern.source + "/g" : pattern.pattern.source}</pre></td>
                                        <td className="patterns-td">{pattern.entropy}</td>
                                        <td className="actions-cell">
                                            <button
                                                className="view-button"
                                                onClick={() => console.log(pattern)}
                                                title="Edit Pattern"
                                            >
                                                <SquareArrowRight size={18} />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </>
                ) : (
                    <div className="empty-state">
                        <AlertTriangle size={48} />
                        <p>No patterns match your search.</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Patterns;