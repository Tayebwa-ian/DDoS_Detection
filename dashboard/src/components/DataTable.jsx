// src/components/DataTable.jsx

import React from 'react';

const DataTable = ({ data }) => (
    <div className="bg-white p-4 rounded-lg shadow-md overflow-x-auto">
        <h3 className="text-xl font-semibold mb-4 text-gray-800">Raw Traffic Records ({data.length})</h3>
        <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
                <tr>
                    {/* Key columns for display */}
                    {['timestamp', 'src_ip', 'dst_ip', 'proto', 'dst_port', 'Packet Length Mean', 'final_label'].map(header => (
                        <th key={header} className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            {header.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </th>
                    ))}
                </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
                {/* Display only the most recent 100 records for performance */}
                {data.slice(0, 100).map((record, index) => (
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
                ))}
            </tbody>
        </table>
        {data.length > 100 && (
             <div className="text-center mt-4 text-gray-500 text-sm">
                ... Showing top 100 of **{data.length}** records.
            </div>
        )}
    </div>
);

export default DataTable;
