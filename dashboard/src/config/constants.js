// src/config/constants.js

// Color scheme for charts
export const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#AF19FF', '#FF0000'];

// Specify the URL path to your constantly updated CSV file.
// IMPORTANT: This must be a path accessible via a web server (e.g., http://localhost:8000/traffic.csv).
// If the CSV is in the public folder of your React project, you can use a relative path like below:
export const CSV_FILE_URL = '~/DDoS_Detection/real_time_detection/data/predictions_log.csv'; 

// Define the interval (in milliseconds) for polling the CSV file for updates (e.g., every 5 seconds)
export const POLLING_INTERVAL = 5000;
