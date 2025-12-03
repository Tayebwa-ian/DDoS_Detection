// src/helpers/dataProcessing.js

/**
 * Parses the raw CSV string into an array of objects, then sorts them by timestamp 
 * in descending order (most current on top).
 * Assumes the first row is the header.
 * @param {string} csvText - The raw CSV content.
 * @param {string} timestampKey - The key/field name containing the timestamp (e.g., 'timestamp').
 * @returns {Array<Object>} - Array of traffic records, sorted by most current first.
 */
export const parseCSV = (csvText, timestampKey = 'timestamp') => { // Added timestampKey argument
    const lines = csvText.trim().split('\n');
    if (lines.length === 0) return [];

    // Use the first line as headers, trimming whitespace
    const headers = lines[0].split(',').map(h => h.trim());
    const data = [];

    for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',');
        if (values.length !== headers.length) continue; // Skip incomplete rows

        let record = {};
        headers.forEach((header, index) => {
            const value = values[index].trim();
            // Attempt to parse numerical values, leaving empty strings as is
            record[header] = isNaN(Number(value)) || value === '' ? value : Number(value);
        });
        data.push(record);
    }
    
    /**
     * Sorts the data by the specified timestamp field in descending order (most current on top).
     */
    data.sort((a, b) => {
        // Handle cases where the timestamp key might not exist or the value is invalid
        if (!a[timestampKey] || !b[timestampKey]) {
            return 0; // Maintain current order if timestamps are missing
        }

        const dateA = new Date(a[timestampKey]);
        const dateB = new Date(b[timestampKey]);

        // Check for invalid dates (Date(null) or Date(undefined) is often valid but incorrect)
        if (isNaN(dateA.getTime()) || isNaN(dateB.getTime())) {
            return 0; // Maintain current order if dates are invalid
        }
        
        // Descending order (newest first): B - A
        // If B is a later date, the result is positive, placing B before A.
        return dateB - dateA;
    });

    return data;
};

/**
 * Aggregates data for the charts (Label Distribution and Protocol Breakdown).
 * @param {Array<Object>} data - The filtered traffic records.
 * @returns {{labelData: Array<Object>, protoData: Array<Object>}} - Aggregated data for charts.
 */
export const aggregateData = (data) => {
    // Logic to count occurrences of final_label
    const labelCounts = data.reduce((acc, curr) => {
        acc[curr.final_label] = (acc[curr.final_label] || 0) + 1;
        return acc;
    }, {});

    // Logic to count occurrences of proto
    const protoCounts = data.reduce((acc, curr) => {
        acc[curr.proto] = (acc[curr.proto] || 0) + 1;
        return acc;
    }, {});

    const labelData = Object.keys(labelCounts).map(key => ({
        name: key,
        value: labelCounts[key]
    }));

    const protoData = Object.keys(protoCounts).map(key => ({
        proto: key,
        count: protoCounts[key]
    }));

    return { labelData, protoData };
};
