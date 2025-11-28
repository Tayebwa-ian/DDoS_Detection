// src/config/constants.js

// Color scheme for charts
export const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#AF19FF', '#FF0000'];

// Specify the URL path to your constantly updated CSV file.
// If the CSV is in the public folder of your React project, you can use a relative path like below:
export const CSV_FILE_URL = 'http://localhost:8000/predictions_log.csv'; 

// Define the interval (in milliseconds) for polling the CSV file for updates (e.g., every 5 seconds)
export const POLLING_INTERVAL = 5000;

// --- NEW CONSTANT FOR PAGINATION ---
export const ROWS_PER_PAGE = 20;
