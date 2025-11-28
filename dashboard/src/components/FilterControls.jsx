// src/components/FilterControls.jsx

import React from 'react';

const FilterControls = ({ filters, onFilterChange, uniqueLabels }) => (
    <div className="p-4 bg-gray-50 rounded-lg shadow-inner">
        <h3 className="text-lg font-semibold mb-3 text-gray-700">🔍 Filter Traffic</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {/* Input fields for IP and Protocol filtering */}
            {['src_ip', 'dst_ip', 'proto'].map(key => (
                <input
                    key={key}
                    type="text"
                    placeholder={`Filter ${key.replace('_', ' ')}`}
                    value={filters[key]}
                    onChange={(e) => onFilterChange(key, e.target.value)}
                    className="p-2 border border-gray-300 rounded text-sm focus:ring-blue-500 focus:border-blue-500"
                />
            ))}
            {/* Dropdown for categorical 'final_label' filtering */}
            <select
                value={filters.final_label}
                onChange={(e) => onFilterChange('final_label', e.target.value)}
                className="p-2 border border-gray-300 rounded text-sm bg-white focus:ring-blue-500 focus:border-blue-500"
            >
                <option value="">All Labels</option>
                {uniqueLabels.map(label => (
                    <option key={label} value={label}>{label}</option>
                ))}
            </select>
        </div>
    </div>
);

export default FilterControls;
