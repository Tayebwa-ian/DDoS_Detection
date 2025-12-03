import React, { useState, useEffect, useMemo, useCallback } from 'react';
import './App.css';
import { parseCSV, aggregateData } from './helpers/dataProcessing';
import { CSV_FILE_URL, POLLING_INTERVAL, ROWS_PER_PAGE } from './config/constants';
import FilterControls from './components/FilterControls';
import SummaryCharts from './components/SummaryCharts';
import DataTable from './components/DataTable';

export default function App() {
    // State to hold ALL incoming traffic records from the server
    const [trafficData, setTrafficData] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    
    // State for pagination: current page number
    const [currentPage, setCurrentPage] = useState(1); 
    
    // State to hold the current filter values from user input
    const [filters, setFilters] = useState({
        src_ip: '',
        dst_ip: '',
        proto: '',
        final_label: '', // This is for the categorical dropdown filter
    });

    /**
     * Retrieves the CSV file content from the specified HTTP URL (http://localhost:8000).
     * This function is run on mount and then periodically by setInterval.
     * @returns {void}
     */
    const fetchTrafficData = useCallback(async () => {
        try {
            const response = await fetch(CSV_FILE_URL);
            
            if (!response.ok) {
                // If the server returns an error status (e.g., 404), log it.
                throw new Error(`HTTP error! status: ${response.status} from ${CSV_FILE_URL}`);
            }

            // Read the response body as plain text (the CSV content)
            const csvText = await response.text();
            
            // Parse the CSV content into structured data
            const parsedData = parseCSV(csvText);
            
            // Update the main state with the new data
            setTrafficData(parsedData);
        } catch (error) {
            console.error("Failed to fetch or process traffic data. Is the Node.js data server running on port 8000?", error);
        } finally {
            setIsLoading(false);
        }
    }, []);

    // --- REAL-TIME DATA POLLING EFFECT ---
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
    // This hook filters ALL records based on the current filter inputs.
    const filteredData = useMemo(() => {
        if (isLoading) return [];

        // Pre-process filter values once for efficiency and case-insensitivity
        const filterSrcIp = filters.src_ip.toLowerCase();
        const filterDstIp = filters.dst_ip.toLowerCase();
        const filterProto = filters.proto.toLowerCase();

        return trafficData.filter(record => {
            // 1. Safe access and lowercasing of record fields (prevents 'toString' error)
            const recordSrcIp = (record.src_ip?.toString() || '').toLowerCase();
            const recordDstIp = (record.dst_ip?.toString() || '').toLowerCase();
            const recordProto = (record.proto?.toString() || '').toLowerCase();
            const recordLabel = record.final_label || '';

            // 2. Partial match check for IPs and Protocol (case-insensitive)
            const matchesSrc = recordSrcIp.includes(filterSrcIp);
            const matchesDst = recordDstIp.includes(filterDstIp);
            const matchesProto = recordProto.includes(filterProto);
            
            // 3. Exact match check for the final_label dropdown
            const matchesLabel = filters.final_label === '' || recordLabel === filters.final_label;

            return matchesSrc && matchesDst && matchesProto && matchesLabel;
        });
    }, [trafficData, filters, isLoading]); // Re-run when data or filters change

    // --- PAGINATION LOGIC ---
    const totalPages = Math.ceil(filteredData.length / ROWS_PER_PAGE);

    // Get the data slice for the current page
    const paginatedData = useMemo(() => {
        const startIndex = (currentPage - 1) * ROWS_PER_PAGE;
        const endIndex = startIndex + ROWS_PER_PAGE;
        return filteredData.slice(startIndex, endIndex);
    }, [filteredData, currentPage]);
    
    // Reset page to 1 whenever the filtered results change (e.g., filter applied or new data received)
    useEffect(() => {
        setCurrentPage(1);
    }, [filteredData]);


    // --- AGGREGATION & UNIQUE LABELS (Memoized) ---
    const { labelData, protoData } = useMemo(() => aggregateData(filteredData), [filteredData]);

    const uniqueLabels = useMemo(() => {
        // Collect all unique labels for the filter dropdown
        const labels = new Set(trafficData.map(d => d.final_label).filter(Boolean));
        return Array.from(labels).sort();
    }, [trafficData]);

    // --- FILTER HANDLER ---
    const handleFilterChange = useCallback((key, value) => {
        // Update the specific filter key with the new value
        setFilters(prev => ({ ...prev, [key]: value }));
    }, []);

    // --- PAGINATION HANDLERS ---
    const handlePageChange = useCallback((page) => {
        // Only allow navigation to valid page numbers
        if (page > 0 && page <= totalPages) {
            setCurrentPage(page);
        }
    }, [totalPages]);


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

                    <div className="flex flex-col lg:flex-row gap-6">
                        {/* LEFT COLUMN: Traffic Records Table */}
                        <div className="lg:w-[65%]">
                            <h2 className="text-2xl font-semibold mb-4 text-gray-800">Traffic Records</h2>
                            <DataTable 
                                data={paginatedData}
                                totalRecords={filteredData.length}
                                currentPage={currentPage}
                                totalPages={totalPages}
                                onPageChange={handlePageChange}
                            />
                        </div>

                        {/* RIGHT COLUMN: Summary Analytics Charts */}
                        <div className="lg:w-[35%]">
                            <h2 className="text-2xl font-semibold mb-4 text-gray-800">Summary Analytics</h2>
                            <SummaryCharts labelData={labelData} protoData={protoData} />
                        </div>
                    </div>
                </>
            )}
            
        </div>
    );
}