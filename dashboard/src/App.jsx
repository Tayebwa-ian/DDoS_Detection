// src/App.jsx

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { parseCSV, aggregateData } from './helpers/dataProcessing';
import { CSV_FILE_URL, POLLING_INTERVAL } from './config/constants';
import FilterControls from './components/FilterControls';
import SummaryCharts from './components/SummaryCharts';
import DataTable from './components/DataTable';

export default function App() {
    // State to hold ALL incoming traffic records
    const [trafficData, setTrafficData] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    
    // State to hold the current filter values
    const [filters, setFilters] = useState({
        src_ip: '',
        dst_ip: '',
        proto: '',
        final_label: '',
    });

    /**
     * Retrieves the CSV file content from the specified URL.
     * @returns {void}
     */
    const fetchTrafficData = useCallback(async () => {
        try {
            const response = await fetch(CSV_FILE_URL);
            
            // Check for successful HTTP response
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            // Read the response body as plain text (the CSV content)
            const csvText = await response.text();
            
            // Parse the CSV content into structured data
            const parsedData = parseCSV(csvText);
            
            // NOTE: For real-time updates, we overwrite the previous data.
            // If you need to append new data only, more complex logic is required
            // (e.g., checking timestamps and merging). For now, we load the whole updated file.
            setTrafficData(parsedData);
        } catch (error) {
            console.error("Failed to fetch or process traffic data:", error);
        } finally {
            setIsLoading(false);
        }
    }, []);

    // --- REAL-TIME DATA POLLING ---
    useEffect(() => {
        // 1. Initial data load
        fetchTrafficData();

        // 2. Set up the interval for periodic data retrieval
        const intervalId = setInterval(() => {
            fetchTrafficData();
        }, POLLING_INTERVAL); 

        // Cleanup function to stop the interval when the component unmounts
        return () => clearInterval(intervalId);
    }, [fetchTrafficData]);

    // --- FILTERING LOGIC (Memoized for performance) ---
    const filteredData = useMemo(() => {
        // Check if data is still loading
        if (isLoading) return [];

        return trafficData.filter(record => {
            // Case-insensitive filtering using includes()
            const matchesSrc = record.src_ip.toString().includes(filters.src_ip);
            const matchesDst = record.dst_ip.toString().includes(filters.dst_ip);
            const matchesProto = record.proto.toString().includes(filters.proto);
            
            // Exact match filtering for categorical label
            const matchesLabel = filters.final_label === '' || record.final_label === filters.final_label;

            return matchesSrc && matchesDst && matchesProto && matchesLabel;
        });
    }, [trafficData, filters, isLoading]);

    // --- AGGREGATION & UNIQUE LABELS (Memoized) ---
    const { labelData, protoData } = useMemo(() => aggregateData(filteredData), [filteredData]);

    const uniqueLabels = useMemo(() => {
        const labels = new Set(trafficData.map(d => d.final_label).filter(Boolean));
        return Array.from(labels).sort();
    }, [trafficData]);

    // --- FILTER HANDLER ---
    const handleFilterChange = useCallback((key, value) => {
        setFilters(prev => ({ ...prev, [key]: value }));
    }, []);

    return (
        <div className="p-6 bg-gray-100 min-h-screen font-sans">
            <h1 className="text-3xl font-bold mb-6 text-gray-900">Network Traffic Real-Time Dashboard</h1>
            
            {isLoading && (
                <div className="text-center py-10 text-xl text-blue-600">
                    Loading initial traffic data from server...
                </div>
            )}

            {!isLoading && (
                <>
                    <FilterControls 
                        filters={filters} 
                        onFilterChange={handleFilterChange} 
                        uniqueLabels={uniqueLabels}
                    />
                    
                    <hr className="my-6 border-gray-300" />

                    <h2 className="text-2xl font-semibold mb-4 text-gray-800">Summary Analytics</h2>
                    <SummaryCharts labelData={labelData} protoData={protoData} />

                    <hr className="my-6 border-gray-300" />
                    
                    <h2 className="text-2xl font-semibold mb-4 text-gray-800">Filtered Records</h2>
                    <DataTable data={filteredData} />
                </>
            )}
            
        </div>
    );
}
