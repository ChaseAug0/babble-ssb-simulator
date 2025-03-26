import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap
import matplotlib.ticker as ticker
from mpl_toolkits.mplot3d import Axes3D

# Set the style for matplotlib plots
plt.style.use('ggplot')
sns.set_style("whitegrid")
sns.set_context("paper", font_scale=1.5)
plt.rcParams['figure.figsize'] = [12, 8]

# Colors
COLORS = {
    'primary': '#1f77b4',    # Blue
    'secondary': '#ff7f0e',  # Orange
    'tertiary': '#2ca02c',   # Green
    'quaternary': '#d62728', # Red
    'highlight': '#9467bd',  # Purple
    'gray': '#7f7f7f',       # Gray
}

# Create custom sequential colormap
cmap_colors = [COLORS['primary'], COLORS['tertiary'], COLORS['secondary'], COLORS['quaternary']]
N = 256
custom_cmap = LinearSegmentedColormap.from_list('custom_cmap', cmap_colors, N=N)

# Results directory
RESULTS_DIR = 'results'
OUTPUT_DIR = 'visualizations'

# Create output directory if it doesn't exist
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Load data from CSV files
def load_data(filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    if not os.path.exists(filepath):
        print(f"Warning: File not found: {filepath}")
        return None
    return pd.read_csv(filepath)

# Generate plots for each network profile
def create_byzantine_impact_plots():
    print("Generating Byzantine impact plots for each network profile...")
    
    # Get each network profile data file
    data_files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.csv') and 'all-experiments' not in f]
    
    if not data_files:
        # Try to load the all-experiments.csv instead
        all_data = load_data('all-experiments.csv')
        if all_data is None:
            print("No experiment data found!")
            return
        
        # Split all_data into separate profiles
        network_profiles = all_data['networkProfile'].unique()
        for profile in network_profiles:
            profile_data = all_data[all_data['networkProfile'] == profile]
            
            # Create the plot for this profile
            plot_byzantine_impact(profile_data, f"{profile}_byzantine_impact.png")
    else:
        # Process individual network profile files
        for file in data_files:
            data = load_data(file)
            if data is not None:
                plot_name = os.path.splitext(file)[0] + "_byzantine_impact.png"
                plot_byzantine_impact(data, plot_name)
    
    print("✓ Byzantine impact plots generated")

# Plot Byzantine node impact for a specific network profile
def plot_byzantine_impact(data, output_filename):
    # Filter out failed experiments
    if 'failure' in data.columns:
        data = data[~data['failure'].fillna(False)]
    
    # Get unique Byzantine percentages
    byzantine_percentages = sorted(data['byzantinePercentage'].unique())
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Plot line for each Byzantine percentage
    markers = ['o', 's', '^', 'D', 'v', 'p', '*']
    for i, percentage in enumerate(byzantine_percentages):
        percentage_data = data[data['byzantinePercentage'] == percentage].sort_values('nodeNum')
        
        # Skip if no data for this percentage
        if len(percentage_data) == 0:
            continue
            
        label = f"Byzantine nodes: {percentage}%"
        
        # Plot with error bars
        ax.errorbar(
            percentage_data['nodeNum'],
            percentage_data['meanTime'],
            yerr=percentage_data['stdTime'],
            marker=markers[i % len(markers)],
            markersize=8,
            linewidth=2,
            label=label,
            capsize=5
        )
    
    # Add theoretical threshold line (f = n/3)
    # This line shows where the Byzantine percentage is 33.3% (theoretical limit)
    x_vals = np.linspace(0, data['nodeNum'].max() * 1.1, 100)
    y_theoretical = np.zeros_like(x_vals)
    y_theoretical.fill(np.nan)  # Using NaN for visualization purposes
    ax.plot(x_vals, y_theoretical, 'r--', linewidth=2, alpha=0.7, label="Theoretical BFT limit (33.3%)")
    
    # Add annotation for the theoretical limit
    ax.annotate('Byzantine nodes > n/3\n(system vulnerable)',
                xy=(data['nodeNum'].max() * 0.7, data['meanTime'].max() * 0.8),
                xytext=(data['nodeNum'].max() * 0.7, data['meanTime'].max() * 0.8),
                color=COLORS['quaternary'],
                fontsize=12,
                bbox=dict(boxstyle="round,pad=0.5", fc="white", alpha=0.8))
    
    # Set axis labels and title
    network_name = output_filename.split('_')[0]
    mean_delay = data['networkMean'].iloc[0] if 'networkMean' in data.columns else 'Unknown'
    std_delay = data['networkStd'].iloc[0] if 'networkStd' in data.columns else 'Unknown'
    
    ax.set_xlabel('Total Number of Nodes', fontsize=14)
    ax.set_ylabel('Consensus Time (ms)', fontsize=14)
    ax.set_title(f'Byzantine Impact: Consensus Time vs. Node Count\nNetwork: {network_name} (Mean={mean_delay}s, Std={std_delay}s)', fontsize=16)
    
    # Format axes
    ax.grid(True, alpha=0.3)
    
    # Add legend
    ax.legend(loc='upper left', frameon=True)
    
    # Save figure
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, output_filename), dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"  Plot saved: {output_filename}")

# Create combined visualization of all network profiles
def create_combined_visualization():
    print("Generating combined network profile visualization...")
    
    # Load all experiment data
    all_data = load_data('all-experiments.csv')
    
    if all_data is None:
        # Try to load individual files and combine them
        data_files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.csv') and 'all-experiments' not in f]
        if not data_files:
            print("No experiment data found!")
            return
            
        all_data = pd.DataFrame()
        for file in data_files:
            data = load_data(file)
            if data is not None:
                # Make sure networkProfile is in the data
                if 'networkProfile' not in data.columns and 'networkMean' not in data.columns:
                    profile_name = os.path.splitext(file)[0]
                    data['networkProfile'] = profile_name
                all_data = pd.concat([all_data, data])
    
    # Filter out failed experiments
    if 'failure' in all_data.columns:
        all_data = all_data[~all_data['failure'].fillna(False)]
    
    # Create a matrix of subplots for different network profiles and byzantine percentages
    network_profiles = sorted(all_data['networkProfile'].unique())
    byzantine_percentages = sorted(all_data['byzantinePercentage'].unique())
    
    # Create subplots grid
    fig, axes = plt.subplots(len(network_profiles), 1, figsize=(14, 6*len(network_profiles)), sharex=True)
    if len(network_profiles) == 1:
        axes = [axes]  # Make it iterable if there's only one profile
    
    # Plot each network profile on a separate subplot
    for i, profile in enumerate(network_profiles):
        ax = axes[i]
        profile_data = all_data[all_data['networkProfile'] == profile]
        
        # Plot line for each Byzantine percentage within this profile
        markers = ['o', 's', '^', 'D', 'v', 'p', '*']
        for j, percentage in enumerate(byzantine_percentages):
            percentage_data = profile_data[profile_data['byzantinePercentage'] == percentage].sort_values('nodeNum')
            
            # Skip if no data for this percentage
            if len(percentage_data) == 0:
                continue
                
            label = f"Byzantine nodes: {percentage}%"
            
            # Plot line with error bars
            ax.errorbar(
                percentage_data['nodeNum'],
                percentage_data['meanTime'],
                yerr=percentage_data['stdTime'],
                marker=markers[j % len(markers)],
                markersize=8,
                linewidth=2,
                label=label if i == 0 else "",  # Only label in the first subplot
                capsize=5
            )
        
        # Set title and labels for this subplot
        mean_delay = profile_data['networkMean'].iloc[0] if 'networkMean' in profile_data.columns else 'Unknown'
        std_delay = profile_data['networkStd'].iloc[0] if 'networkStd' in profile_data.columns else 'Unknown'
        
        ax.set_title(f'Network: {profile} (Mean={mean_delay}s, Std={std_delay}s)', fontsize=14)
        ax.set_ylabel('Consensus Time (ms)', fontsize=12)
        ax.grid(True, alpha=0.3)
        
        # Add y-axis limits for better comparison between plots
        max_time = all_data['meanTime'].max() * 1.1
        ax.set_ylim(0, max_time)
        
        # Add annotation for the theoretical limit
        ax.annotate('n/3 Byzantine node threshold',
                    xy=(all_data['nodeNum'].max() * 0.8, all_data['meanTime'].max() * 0.5),
                    xytext=(all_data['nodeNum'].max() * 0.8, all_data['meanTime'].max() * 0.5),
                    color=COLORS['quaternary'],
                    fontsize=10,
                    bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.7))
    
    # Add common x-axis label
    fig.text(0.5, 0.04, 'Total Number of Nodes', ha='center', fontsize=14)
    
    # Add common legend
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', bbox_to_anchor=(0.5, 1.02), ncol=len(byzantine_percentages))
    
    # Add common title
    fig.suptitle('Comparison of Consensus Time Across Network Conditions', fontsize=16, y=1.05)
    
    # Save figure
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'combined_network_profiles.png'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Combined network profile visualization generated")

# Create normalized scaling plot
def create_normalized_scaling_plot():
    print("Generating normalized scaling plot...")
    
    # Load all experiment data
    all_data = load_data('all-experiments.csv')
    
    if all_data is None:
        print("No experiment data found!")
        return
    
    # Filter out failed experiments
    if 'failure' in all_data.columns:
        all_data = all_data[~all_data['failure'].fillna(False)]
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Get unique Byzantine percentages
    byzantine_percentages = sorted(all_data['byzantinePercentage'].unique())
    
    # Plot normalized scaling for each Byzantine percentage
    markers = ['o', 's', '^', 'D', 'v', 'p', '*']
    
    # For this plot, we'll focus on one network profile (fastest)
    network_profiles = sorted(all_data['networkProfile'].unique())
    fastest_profile = network_profiles[0]  # Assuming sorted by speed
    
    profile_data = all_data[all_data['networkProfile'] == fastest_profile]
    
    for i, percentage in enumerate(byzantine_percentages):
        percentage_data = profile_data[profile_data['byzantinePercentage'] == percentage].sort_values('nodeNum')
        
        # Skip if no data for this percentage
        if len(percentage_data) == 0:
            continue
        
        # Calculate normalized consensus time (time per node)
        percentage_data['time_per_node'] = percentage_data['meanTime'] / percentage_data['nodeNum']
        
        # Plot
        label = f"Byzantine nodes: {percentage}%"
        ax.plot(
            percentage_data['nodeNum'],
            percentage_data['time_per_node'],
            marker=markers[i % len(markers)],
            markersize=8,
            linewidth=2,
            label=label
        )
    
    # Add reference lines for O(n) and O(n²) scaling
    x_vals = np.linspace(4, all_data['nodeNum'].max(), 100)
    
    # Find a good scaling factor for reference lines
    scaling_factor = profile_data['time_per_node'].median() / profile_data['nodeNum'].median()
    
    # O(1) - constant time per node
    ax.plot(x_vals, np.ones_like(x_vals) * scaling_factor * 10, 'k:', linewidth=1.5, alpha=0.5, label="O(1) scaling")
    
    # O(log n) - logarithmic scaling
    ax.plot(x_vals, scaling_factor * np.log(x_vals), 'k-.', linewidth=1.5, alpha=0.5, label="O(log n) scaling")
    
    # O(n) - linear scaling
    #ax.plot(x_vals, scaling_factor * x_vals, 'k--', linewidth=1.5, alpha=0.5, label="O(n) scaling")
    
    # Set axis labels and title
    ax.set_xlabel('Total Number of Nodes', fontsize=14)
    ax.set_ylabel('Consensus Time per Node (ms/node)', fontsize=14)
    ax.set_title(f'Normalized Scaling: Consensus Time per Node vs. Node Count\nNetwork: {fastest_profile}', fontsize=16)
    
    # Set y-axis to log scale for better visualization of scaling behaviors
    ax.set_yscale('log')
    
    # Format axes
    ax.grid(True, alpha=0.3)
    
    # Add legend
    ax.legend(loc='best', frameon=True)
    
    # Save figure
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'normalized_scaling.png'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Normalized scaling plot generated")

# Create 3D visualization of network delay vs nodes vs Byzantine ratio
def create_3d_visualization():
    print("Generating 3D visualization...")
    
    # Load all experiment data
    all_data = load_data('all-experiments.csv')
    
    if all_data is None:
        print("No experiment data found!")
        return
    
    # Filter out failed experiments
    if 'failure' in all_data.columns:
        all_data = all_data[~all_data['failure'].fillna(False)]
    
    # Create figure
    fig = plt.figure(figsize=(15, 10))
    ax = fig.add_subplot(111, projection='3d')
    
    # Group by network profile, node count, and Byzantine percentage
    network_profiles = sorted(all_data['networkProfile'].unique())
    
    # Set up colors for different network profiles
    profile_colors = [COLORS['primary'], COLORS['tertiary'], COLORS['secondary'], COLORS['quaternary']]
    
    # Set up markers for different Byzantine percentages
    byzantine_percentages = sorted(all_data['byzantinePercentage'].unique())
    markers = ['o', 's', '^', 'D']
    
    # Create a surface plot
    for i, profile in enumerate(network_profiles):
        profile_data = all_data[all_data['networkProfile'] == profile]
        
        # For each Byzantine percentage
        for j, percentage in enumerate(byzantine_percentages):
            percentage_data = profile_data[profile_data['byzantinePercentage'] == percentage].sort_values('nodeNum')
            
            # Skip if no data for this combination
            if len(percentage_data) == 0:
                continue
            
            # Plot 3D scatter
            ax.scatter(
                percentage_data['nodeNum'],
                percentage_data['byzantinePercentage'],
                percentage_data['meanTime'],
                color=profile_colors[i % len(profile_colors)],
                marker=markers[j % len(markers)],
                s=100,
                alpha=0.7,
                label=f"{profile}, {percentage}% Byzantine" if j == 0 else ""
            )
            
            # Connect points with lines
            ax.plot(
                percentage_data['nodeNum'],
                percentage_data['byzantinePercentage'],
                percentage_data['meanTime'],
                color=profile_colors[i % len(profile_colors)],
                alpha=0.4
            )
    
    # Set axis labels
    ax.set_xlabel('Total Number of Nodes', fontsize=12)
    ax.set_ylabel('Byzantine Nodes (%)', fontsize=12)
    ax.set_zlabel('Consensus Time (ms)', fontsize=12)
    
    # Set title
    ax.set_title('3D View: Impact of Node Count, Byzantine Percentage, and Network Conditions', fontsize=14)
    
    # Adjust view angle for better visualization
    ax.view_init(elev=30, azim=45)
    
    # Add legend
    ax.legend(loc='upper left', frameon=True)
    
    # Save figure
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '3d_visualization.png'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ 3D visualization generated")

# Create heatmap of node count vs Byzantine percentage for each network profile
def create_heatmaps():
    print("Generating heatmaps...")
    
    # Load all experiment data
    all_data = load_data('all-experiments.csv')
    
    if all_data is None:
        print("No experiment data found!")
        return
    
    # Filter out failed experiments
    if 'failure' in all_data.columns:
        all_data = all_data[~all_data['failure'].fillna(False)]
    
    # Get unique network profiles
    network_profiles = sorted(all_data['networkProfile'].unique())
    
    # Create a heatmap for each network profile
    for profile in network_profiles:
        profile_data = all_data[all_data['networkProfile'] == profile]
        
        # Create pivot table
        pivot = profile_data.pivot_table(
            index='nodeNum',
            columns='byzantinePercentage',
            values='meanTime',
            aggfunc='mean'
        )
        
        # Create figure
        plt.figure(figsize=(10, 8))
        
        # Plot heatmap
        sns.heatmap(
            pivot,
            annot=True,
            fmt=".0f",
            cmap=custom_cmap,
            linewidths=0.5,
            cbar_kws={'label': 'Consensus Time (ms)'}
        )
        
        # Set title and labels
        mean_delay = profile_data['networkMean'].iloc[0] if 'networkMean' in profile_data.columns else 'Unknown'
        std_delay = profile_data['networkStd'].iloc[0] if 'networkStd' in profile_data.columns else 'Unknown'
        
        plt.title(f'Heatmap: Node Count vs. Byzantine Percentage\nNetwork: {profile} (Mean={mean_delay}s, Std={std_delay}s)', fontsize=14)
        plt.xlabel('Byzantine Nodes (%)', fontsize=12)
        plt.ylabel('Total Number of Nodes', fontsize=12)
        
        # Save figure
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, f'{profile}_heatmap.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    print("✓ Heatmaps generated")

# Create comprehensive visualization with multiple subplots
def create_comprehensive_visualization():
    print("Generating comprehensive visualization...")
    
    # Load all experiment data
    all_data = load_data('all-experiments.csv')
    
    if all_data is None:
        print("No experiment data found!")
        return
    
    # Filter out failed experiments
    if 'failure' in all_data.columns:
        all_data = all_data[~all_data['failure'].fillna(False)]
    
    # Get unique network profiles and Byzantine percentages
    network_profiles = sorted(all_data['networkProfile'].unique())
    byzantine_percentages = sorted(all_data['byzantinePercentage'].unique())
    
    # Create a grid of subplots
    fig = plt.figure(figsize=(20, 15))
    gs = fig.add_gridspec(len(network_profiles), len(byzantine_percentages))
    
    # Plot each network profile vs Byzantine percentage combination
    for i, profile in enumerate(network_profiles):
        profile_data = all_data[all_data['networkProfile'] == profile]
        
        for j, percentage in enumerate(byzantine_percentages):
            ax = fig.add_subplot(gs[i, j])
            
            percentage_data = profile_data[profile_data['byzantinePercentage'] == percentage].sort_values('nodeNum')
            
            # Skip if no data for this combination
            if len(percentage_data) == 0:
                ax.text(0.5, 0.5, 'No Data', ha='center', va='center')
                continue
            
            # Plot line with error bars
            ax.errorbar(
                percentage_data['nodeNum'],
                percentage_data['meanTime'],
                yerr=percentage_data['stdTime'],
                marker='o',
                markersize=6,
                linewidth=2,
                capsize=3
            )
            
            # Set subplot title
            ax.set_title(f'{profile}, {percentage}% Byzantine', fontsize=10)
            
            # Only show y-axis labels on the leftmost column
            if j == 0:
                ax.set_ylabel('Consensus Time (ms)', fontsize=10)
            
            # Only show x-axis labels on the bottom row
            if i == len(network_profiles)-1:
                ax.set_xlabel('Nodes', fontsize=10)
            
            # Apply grid
            ax.grid(True, alpha=0.3)
            
            # Scale y-axis consistently across all subplots
            ax.set_ylim(0, all_data['meanTime'].max() * 1.1)
    
    # Add a common title
    fig.suptitle('Comprehensive View: Consensus Time Across All Configurations', fontsize=16)
    
    # Adjust layout
    plt.tight_layout(rect=[0, 0, 1, 0.97])
    
    # Save figure
    plt.savefig(os.path.join(OUTPUT_DIR, 'comprehensive_visualization.png'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print("✓ Comprehensive visualization generated")

# Main function to generate all visualizations
def main():
    print("Starting visualization generation...")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    # Generate all visualizations
    create_byzantine_impact_plots()
    create_combined_visualization()
    create_normalized_scaling_plot()
    create_3d_visualization()
    create_heatmaps()
    create_comprehensive_visualization()
    
    print("\nAll visualizations complete! Output saved to:", OUTPUT_DIR)

if __name__ == "__main__":
    main()