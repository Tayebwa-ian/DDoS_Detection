// src/helpers/dataProcessing.js

/**
 * Parses the raw CSV string into an array of objects.
 * Assumes the first row is the header.
 * @param {string} csvText - The raw CSV content.
 * @returns {Array<Object>} - Array of traffic records.
 */
export const parseCSV = (csvText) => {
    // Standard CSV parsing logic
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
    // console.log(data);
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
