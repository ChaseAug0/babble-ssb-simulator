#!/bin/bash
# attack-runner.sh - Run all consensus protocol attacks and collect results

echo "BFT Consensus Protocol Attack Simulation"
echo "========================================"

# Create results directory
mkdir -p results

# Attack modes
ATTACKERS=(
  "adaptive-attack-strategist"
  "byzantine-attack-coordinator"
  "clock-skew-attacker"
  "equivocation-attacker"
  "fail-stop"
  "logic-bomb-attacker"
  "man-in-the-middle-attacker"
  "message-sequence-manipulator"
  "multi-layer-attack-coordinator"
  "partitioner"
  "signature-forgery-attacker"
  "sync-interfernce-attacker"
)

# Protocols to test
PROTOCOLS=(
  "ssb-babble"
  "pbft"
  "hotstuff-NS"
  "algorand"
  "libraBFT"
  "async-BA"
)

# Node configurations - [byzantineNodeNum, nodeNum]
NODE_CONFIGS=(
  "4 16"
  "8 32"
  "16 64"
)

# Function to update config.js
update_config() {
  local attacker=$1
  local protocol=$2
  local byzantine_nodes=$3
  local total_nodes=$4
  
  cat > config.js << EOF
module.exports = {
  // Node configuration
  nodeNum: ${total_nodes},
  byzantineNodeNum: ${byzantine_nodes},

  // Protocol parameters
  lambda: 1,
  protocol: '${protocol}',

  // Network conditions
  networkDelay: {
    mean: 1.0,
    std: 0.5,
  },

  // Attacker configuration
  attacker: '${attacker}',

  // Other parameters
  logToFile: true,
  repeatTime: 50,

  // Additional Babble specific configuration
  babble: {
    suspendLimit: 200,
    syncInterval: 500,
  }
};
EOF
}

# Results file
RESULTS_FILE="results/attack_results.txt"
echo "BFT Consensus Protocols Attack Results" > $RESULTS_FILE
echo "========================================" >> $RESULTS_FILE
echo "" >> $RESULTS_FILE

# Run all tests
for attacker in "${ATTACKERS[@]}"; do
  echo "Running tests with attacker: $attacker"
  
  for config in "${NODE_CONFIGS[@]}"; do
    read -r byzantine_nodes total_nodes <<< "$config"
    echo "  Node configuration: $byzantine_nodes/$total_nodes"
    
    for protocol in "${PROTOCOLS[@]}"; do
      echo "    Protocol: $protocol"
      
      # Update configuration
      update_config "$attacker" "$protocol" "$byzantine_nodes" "$total_nodes"
      
      # Create output file for this run
      run_id="${attacker}_${protocol}_${byzantine_nodes}_${total_nodes}"
      output_file="results/$run_id.txt"
      
      # Run simulation with timeout (15 minutes)
      echo "      Executing simulation..."
      timeout 15m node main.js > "$output_file" 2>&1
      exit_code=$?
      
      # Check if the command timed out (exit code 124)
      if [ $exit_code -eq 124 ]; then
        echo "      Simulation timed out after 15 minutes"
        echo "ERROR: Simulation timed out after 15 minutes." > "$output_file"
        echo "The simulation was terminated due to exceeding the time limit." >> "$output_file"
      fi
      
      # Append separator and header to results file
      echo "----------------------------------------" >> $RESULTS_FILE
      echo "Attack: $attacker" >> $RESULTS_FILE
      echo "Protocol: $protocol" >> $RESULTS_FILE
      echo "Nodes: $total_nodes (Byzantine: $byzantine_nodes)" >> $RESULTS_FILE
      echo "" >> $RESULTS_FILE
      
      # Check if simulation was successful
      if [ $exit_code -eq 0 ]; then
        echo "      Completed successfully"
        # Append results
        cat "$output_file" >> $RESULTS_FILE
      else
        echo "      Failed with exit code $exit_code"
        echo "ERROR: Simulation failed with exit code $exit_code" >> $RESULTS_FILE
        cat "$output_file" >> $RESULTS_FILE
      fi
      
      echo "" >> $RESULTS_FILE
    done
  done
done

echo "All tests completed. Results saved to $RESULTS_FILE"