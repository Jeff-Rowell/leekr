import {
    AlertTriangle,
    ChevronDown,
    ChevronUp,
    Search
} from 'lucide-react';
import React, { useEffect, useState } from 'react';
import { useAppContext } from '../../popup/AppContext';
import { Pattern } from '../../types/patterns.types';

// Pagination constants
const ITEMS_PER_PAGE = 10;

export const Detectors: React.FC<{ familyname: string }> = ({ familyname }) => {
    const { data } = useAppContext();
    const [currentPage, setCurrentPage] = useState(1);
    const [filteredPatterns, setFilteredPatterns] = useState<Pattern[]>([]);
    const [sortField, setSortField] = useState<'name' | 'family-name' | 'pattern' | 'entropy'>('name');
    const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
    const [searchQuery, setSearchQuery] = useState("");

    useEffect(() => {
        let patterns = [...Object.values(data.patterns)];
        const hasSearchQuery = searchQuery && searchQuery.trim() !== "" ? true : false;
        const hasFamilyNameQuery = familyname && familyname.trim() !== "" ? true : false;
        if (hasSearchQuery || hasFamilyNameQuery) {
            const query = hasSearchQuery ? searchQuery.toLowerCase() : familyname.toLowerCase();
            patterns = patterns.filter(pattern =>
                pattern.name.toLowerCase().includes(query) ||
                pattern.familyName.toLowerCase().includes(query)
            );
        }

        patterns.sort((a, b) => {
            if (sortField === 'name') {
                return sortDirection === 'asc'
                    ? a.name.localeCompare(b.name)
                    : b.name.localeCompare(a.name);
            } else if (sortField === 'family-name') {
                return sortDirection === 'asc'
                    ? a.familyName.localeCompare(b.familyName)
                    : b.familyName.localeCompare(a.familyName);
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
    }, [data.patterns, searchQuery, sortField, sortDirection, familyname]);

    const totalPages = Math.ceil(filteredPatterns.length / ITEMS_PER_PAGE);
    const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
    const paginatedPatterns = filteredPatterns.slice(startIndex, startIndex + ITEMS_PER_PAGE);

    const handleSortChange = (field: 'name' | 'family-name' | 'pattern' | 'entropy') => {
        if (sortField === field) {
            setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
        } else {
            setSortField(field);
            setSortDirection('asc');
        }
    };

    const renderSortIcon = (field: 'name' | 'family-name' | 'pattern' | 'entropy') => {
        if (sortField === field) {
            return sortDirection === 'asc' ? <ChevronUp size={16} /> : <ChevronDown size={16} />;
        }
        return <ChevronDown size={16} className="sort-icon-default" />;
    };

    return (
        <div className="tab-content">
            <h3>Detectors</h3>
            <div className="search-container">
                <div className="filter-row">
                    <div className="filter-item">
                        <div className="search-box">
                            <Search size={20} />
                            <input
                                type="text"
                                placeholder="Search detectors..."
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
                                <col style={{ width: '15%' }} />
                                <col style={{ width: '15%' }} />
                                <col style={{ width: '65%' }} />
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
                                    <th className="patterns-th" onClick={() => handleSortChange('family-name')}>
                                        <div className="sortable-header">
                                            <span>Family Name</span>
                                            {renderSortIcon('family-name')}
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
                                </tr>
                            </thead>
                            <tbody>
                                {paginatedPatterns.map((pattern, index) => (
                                    <tr key={index}>
                                        <td className="patterns-td">{pattern.name}</td>
                                        <td className="patterns-td">{pattern.familyName}</td>
                                        <td className="patterns-td"><pre className='pattern-pre'>{pattern.global ? "/" + pattern.pattern.source + "/g" : pattern.pattern.source}</pre></td>
                                        <td className="patterns-td">{pattern.entropy}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </>
                ) : (
                    <div className="empty-state">
                        <AlertTriangle size={48} />
                        <p>No detectors match your search.</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Detectors;