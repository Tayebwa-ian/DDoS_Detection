// src/components/SummaryCharts.jsx

import React from 'react';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from 'recharts';
// Assuming COLORS is an array of colors, but we'll define the needed colors locally for clarity.
// import { COLORS } from '../config/constants'; // No longer strictly needed for Pie Chart, but kept for Bar Chart fallback

// --- Custom Color Mapping Function ---
/**
 * Determines the color for a Pie Chart segment based on its traffic label.
 * @param {string} label - The traffic label (e.g., 'BENIGN', 'MALICIOUS').
 * @returns {string} - The hex color code.
 */
const getLabelColor = (label) => {
    // Standardizing the label to uppercase for robust matching
    const upperLabel = label ? label.toUpperCase() : '';

    if (upperLabel.includes('BENIGN')) {
        return '#4ade80'; // A bright, standard green
    }
    if (upperLabel.includes('MALICIOUS')) {
        return '#f87171'; // A bright, standard red
    }
    
    // Fallback for any other labels (like 'UNKNOWN' or specific attack types)
    return '#6b7280'; // A neutral gray 
};

const SummaryCharts = ({ labelData, protoData }) => (
    <div className="flex flex-col gap-6">
        {/* Traffic Label Distribution Pie Chart */}
        <div className="bg-white p-4 rounded-lg shadow-md">
            <h3 className="text-xl font-semibold mb-2 text-center text-gray-800">Traffic Label Distribution</h3>
            <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                    <Pie
                        data={labelData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={100}
                        innerRadius={60}
                        paddingAngle={2}
                    >
                        {labelData.map((entry, index) => (
                            // >>> MODIFICATION HERE: Using getLabelColor based on entry.name <<<
                            <Cell 
                                key={`cell-${index}`} 
                                fill={getLabelColor(entry.name)} 
                            />
                        ))}
                    </Pie>
                    <Tooltip />
                    <Legend layout="horizontal" align="center" verticalAlign="bottom" />
                </PieChart>
            </ResponsiveContainer>
        </div>
        
        {/* Protocol Breakdown Bar Chart */}
        <div className="bg-white p-4 rounded-lg shadow-md">
            <h3 className="text-xl font-semibold mb-2 text-center text-gray-800">Protocol Breakdown</h3>
            <ResponsiveContainer width="100%" height={300}>
                <BarChart data={protoData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <XAxis dataKey="proto" stroke="#333" />
                    <YAxis stroke="#333" />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="count" fill="#82ca9d" name="Packet Count" /> 
                </BarChart>
            </ResponsiveContainer>
        </div>
    </div>
);

export default SummaryCharts;
