// fileServer.js

const http = require('http');
const fs = require('fs');
const path = require('path');

// --- CONFIGURATION ---
const PORT = 8000;
// CRUCIAL: Set the absolute path to the directory containing your CSV file.
// Adjust this path to match your environment exactly.
const DATA_PATH = '/home/passwd/DDoS_Detection/real_time_detection/data'; 
const FILENAME = 'predictions_log.csv';
const FILE_FULL_PATH = path.join(DATA_PATH, FILENAME);
// ---------------------

const server = http.createServer((req, res) => {
    if (req.url === `/${FILENAME}`) {
        
        // 1. CHECK FILE EXISTENCE FIRST
        fs.stat(FILE_FULL_PATH, (err, stats) => {
            if (err) {
                // If file doesn't exist (ENOENT) or other error, send 404/500 immediately.
                console.error(`Error serving file ${FILENAME}:`, err.message);
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end(`File not found or access error: ${err.message}`);
                return; // Stop execution
            }

            // 2. FILE EXISTS: Set headers and pipe the stream
            res.writeHead(200, { 
                'Content-Type': 'text/csv',
                'Access-Control-Allow-Origin': '*', 
                'Cache-Control': 'no-cache' 
            });

            const readStream = fs.createReadStream(FILE_FULL_PATH);
            readStream.pipe(res);
            
            // Clean up the stream if any subsequent errors occur
            readStream.on('error', (streamErr) => {
                console.error(`Stream error during transmission: ${streamErr.message}`);
                // Since headers were already sent, just close the response connection
                res.end(); 
            });
        });

    } else {
        // ... (Default status message remains the same)
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Data server is running. Serving: ${FILENAME} at http://localhost:${PORT}/${FILENAME}`);
    }
});

server.listen(PORT, () => {
    console.log(`\nData Server is running on http://localhost:${PORT}`);
    console.log(`\nServing data from: ${FILE_FULL_PATH}`);
    console.log('Ensure this server remains running while the dashboard is active.');
});
