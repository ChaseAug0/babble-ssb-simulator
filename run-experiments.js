'use strict';

const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');

// Ensure results directory exists
const RESULTS_DIR = path.join(__dirname, 'results');
if (!fs.existsSync(RESULTS_DIR)) {
    fs.mkdirSync(RESULTS_DIR);
}

// Base configuration
const baseConfig = {
    protocol: 'ssb-babble',
    lambda: 1,
    attacker: 'babble-attacker',
    logToFile: true,
    repeatTime: 20, // Reduced for faster test runs
    babble: {
        suspendLimit: 200,
        syncInterval: 500,
    }
};

// Network condition profiles - varying mean and std
const networkProfiles = [
    { mean: 0.1, std: 0.05, name: 'fast-stable' },      // Fast network with low variance
    { mean: 0.5, std: 0.2, name: 'medium-stable' },     // Medium speed with moderate variance
    { mean: 1.0, std: 0.5, name: 'slow-variable' },     // Slow network with high variance
    { mean: 2.0, std: 1.0, name: 'very-slow-unstable' } // Very slow network with very high variance
];

// Node configurations to test with total count and Byzantine percentage
// We'll use more granular steps for better visualization
const nodeConfigs = [
    // Format: [total nodes, byzantine percentage]
    [4, 0], [4, 10], [4, 20], [4, 30],
    [10, 0], [10, 10], [10, 20], [10, 30],
    [20, 0], [20, 10], [20, 20], [20, 30],
    [36, 0], [36, 10], [36, 20], [36, 30],
    [50, 0], [50, 10], [50, 20], [50, 30],
    [75, 0], [75, 10], [75, 20], [75, 30],
    [100, 0], [100, 10], [100, 20], [100, 30]
];

// Run all experiments
async function runAllExperiments() {
    console.log("Starting BFT-Simulator experiments...");

    // Create a master results array that will contain all experiments
    const masterResults = [];

    // For each network profile
    for (const profile of networkProfiles) {
        console.log(`\n=== Testing with network profile: ${profile.name} ===`);
        console.log(`Mean delay: ${profile.mean}s, Standard deviation: ${profile.std}s`);

        const results = [];

        // For each node configuration
        for (const [nodeCount, byzantinePercentage] of nodeConfigs) {
            const byzantineCount = Math.floor(nodeCount * byzantinePercentage / 100);
            console.log(`\nRunning with ${nodeCount} total nodes, ${byzantineCount} Byzantine nodes (${byzantinePercentage}%)`);

            // Create configuration
            const config = JSON.parse(JSON.stringify(baseConfig));
            config.nodeNum = nodeCount;
            config.byzantineNodeNum = byzantineCount;
            config.networkDelay = {
                mean: profile.mean,
                std: profile.std
            };

            // Write configuration to file
            fs.writeFileSync('config.js', `module.exports = ${JSON.stringify(config, null, 2)};`);

            try {
                // Run simulation and capture output
                const output = execSync('node main.js', { encoding: 'utf8' });

                // Parse results from output
                const result = parseSimulationOutput(output, nodeCount, byzantineCount, byzantinePercentage);

                // Add network profile info to result
                result.networkProfile = profile.name;
                result.networkMean = profile.mean;
                result.networkStd = profile.std;

                results.push(result);
                masterResults.push(result);

                console.log(`Completed: ${JSON.stringify(result)}`);
            } catch (error) {
                console.error(`Error running simulation with ${nodeCount} nodes, ${byzantineCount} Byzantine nodes:`);
                console.error(error.message);

                // Add a failed result marker
                const failedResult = {
                    nodeNum: nodeCount,
                    byzantineNodeNum: byzantineCount,
                    byzantinePercentage: byzantinePercentage,
                    networkProfile: profile.name,
                    networkMean: profile.mean,
                    networkStd: profile.std,
                    failure: true,
                    error: error.message.substring(0, 200) // Just the beginning of the error
                };

                results.push(failedResult);
                masterResults.push(failedResult);
            }
        }

        // Save results to CSV for this network profile
        saveToCSV(results, `${profile.name}.csv`);
    }

    // Save the master results containing all experiments
    saveToCSV(masterResults, 'all-experiments.csv');

    console.log("\nAll experiments completed!");
}

// Parse simulation output to extract relevant metrics
function parseSimulationOutput(output, nodeCount, byzantineCount, byzantinePercentage) {
    // Initialize result object with configuration parameters
    const result = {
        nodeNum: nodeCount,
        byzantineNodeNum: byzantineCount,
        byzantinePercentage: byzantinePercentage
    };

    // Extract time usage
    const timeMatch = output.match(/Time usage \(ms\): \(mean, std\) = \(([^,]+), ([^)]+)\), median = ([^\s]+)/);
    if (timeMatch) {
        result.meanTime = parseFloat(timeMatch[1]);
        result.stdTime = parseFloat(timeMatch[2]);
        result.medianTime = parseFloat(timeMatch[3]);
    }

    // Extract message count
    const msgMatch = output.match(/Message count:\s+\(mean, std\) = \(([^,]+), ([^)]+)\)/);
    if (msgMatch) {
        result.meanMsgCount = parseFloat(msgMatch[1]);
        result.stdMsgCount = parseFloat(msgMatch[2]);
    }

    return result;
}

// Save results to CSV file
function saveToCSV(results, filename) {
    if (results.length === 0) return;

    // Get headers from first result
    const headers = Object.keys(results[0]);

    // Create CSV content
    let csvContent = headers.join(',') + '\n';

    // Add rows
    results.forEach(result => {
        const row = headers.map(header => {
            const value = result[header];
            if (value === undefined || value === null) return '';
            return typeof value === 'string' && value.includes(',') ? `"${value}"` : value;
        }).join(',');
        csvContent += row + '\n';
    });

    // Write to file
    const filePath = path.join(RESULTS_DIR, filename);
    fs.writeFileSync(filePath, csvContent);
    console.log(`Results saved to ${filePath}`);
}

// Run all experiments
runAllExperiments().catch(err => {
    console.error('Error running experiments:', err);
});