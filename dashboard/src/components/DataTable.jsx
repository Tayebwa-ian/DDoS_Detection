// src/components/DataTable.jsx

import React from 'react';
import { ROWS_PER_PAGE } from '../config/constants';

const DataTable = ({ data, totalRecords, currentPage, totalPages, onPageChange }) => {
    
    // Determine if any filtering is active for display text
    const isFiltering = totalRecords !== data.length * totalPages;
    
    // Calculate the range of records currently displayed
    const recordsStart = totalRecords === 0 ? 0 : (currentPage - 1) * ROWS_PER_PAGE + 1;
    const recordsEnd = Math.min(currentPage * ROWS_PER_PAGE, totalRecords);

    return (
        <div className="bg-white p-4 rounded-lg shadow-md overflow-x-auto">
            <h3 className="text-xl font-semibold mb-4 text-gray-800">
                {isFiltering ? 'Filtered Records' : 'All Records'} ({totalRecords})
            </h3>
            
            <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                    <tr>
                        {/* Headers */}
                        {['timestamp', 'src_ip', 'dst_ip', 'proto', 'dst_port', 'Packet Length Mean', 'final_label'].map(header => (
                            <th key={header} className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                {header.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </th>
                        ))}
                    </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                    {/* Data Rows */}
                    {data.length > 0 ? (
                        data.map((record, index) => (
                            <tr key={index} className={record.final_label !== 'BENIGN' ? 'bg-red-50 hover:bg-red-100' : 'hover:bg-gray-50'}>
                                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-900">{record.timestamp}</td>
                                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-900">{record.src_ip}</td>
                                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-900">{record.dst_ip}</td>
                                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-900">{record.proto}</td>
                                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-900">{record.dst_port}</td>
                                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-900">{record['Packet Length Mean']}</td>
                                <td className={`px-3 py-2 whitespace-nowrap text-sm font-semibold ${record.final_label !== 'BENIGN' ? 'text-red-600' : 'text-green-600'}`}>
                                    {record.final_label}
                                </td>
                            </tr>
                        ))
                    ) : (
                        <tr>
                            <td colSpan="7" className="px-6 py-4 text-center text-gray-500">
                                No records found matching the current filters.
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
            
            {/* --- PAGINATION CONTROLS --- */}
            {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4">
                    {/* Page Info */}
                    <div className="text-sm text-gray-700">
                        Showing <span className="font-semibold">{recordsStart}</span> to <span className="font-semibold">{recordsEnd}</span> of <span className="font-semibold">{totalRecords}</span> results.
                    </div>

                    {/* Navigation Buttons */}
                    <div className="flex space-x-2">
                        <button
                            // Decrement page number
                            onClick={() => onPageChange(currentPage - 1)}
                            disabled={currentPage === 1}
                            className={`px-3 py-1 border rounded-md text-sm transition-colors ${currentPage === 1 ? 'bg-gray-200 text-gray-400 cursor-not-allowed' : 'bg-white hover:bg-gray-100'}`}
                        >
                            Previous
                        </button>
                        
                        {/* Current Page Indicator */}
                        <div className="px-3 py-1 border rounded-md text-sm bg-blue-500 text-white font-medium">
                            Page {currentPage} of {totalPages}
                        </div>
                        
                        <button
                            // Increment page number
                            onClick={() => onPageChange(currentPage + 1)}
                            disabled={currentPage === totalPages}
                            className={`px-3 py-1 border rounded-md text-sm transition-colors ${currentPage === totalPages ? 'bg-gray-200 text-gray-400 cursor-not-allowed' : 'bg-white hover:bg-gray-100'}`}
                        >
                            Next
                        </button>
                    </div>
                </div>
            )}
            
        </div>
    );
};

export default DataTable;
