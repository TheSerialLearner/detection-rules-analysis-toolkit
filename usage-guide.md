# Security Rule Analysis Toolkit - Installation and Usage Guide

This toolkit provides a comprehensive set of tools for analyzing and grouping similar security detection rules from multiple repositories (Sigma, Splunk, and Elastic).

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Output Structure](#output-structure)
6. [Advanced Configuration](#advanced-configuration)
7. [Troubleshooting](#troubleshooting)

## Overview

The Security Rule Analysis Toolkit allows you to:
- Download and parse rules from multiple security rule repositories
- Group similar rules using various clustering and similarity techniques
- Categorize rules based on MITRE ATT&CK tactics and techniques
- Extract common themes and topics from rule descriptions
- Generate comprehensive reports and visualizations

## Features

### Rule Collection
- Supports Sigma, Splunk, and Elastic security rule formats
- Handles different file formats (YAML, TOML)
- Extracts key metadata from each rule format

### Similarity Analysis
- K-means clustering with TF-IDF vectorization
- Direct rule-to-rule similarity scoring with customizable thresholds
- Network graph visualization of rule relationships
- t-SNE projection for dimensionality reduction

### Categorization
- MITRE ATT&CK framework mapping
- Topic modeling using Non-negative Matrix Factorization (NMF)
- Common detection pattern extraction (Event IDs, Registry keys, File paths)

### Visualization
- Network graphs of similar rules
- Topic heat maps and word clouds
- MITRE ATT&CK distribution charts
- Interactive visualizations

## Installation

### Prerequisites
- Python 3.8 or higher
- Git (for repository cloning)

### Setup

1. Clone this repository:
```bash
git clone https://github.com/yourusername/security-rule-analysis.git
cd security-rule-analysis
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

The `requirements.txt` file should contain:
```
pandas>=1.3.0
numpy>=1.20.0
scikit-learn>=0.24.0
matplotlib>=3.4.0
seaborn>=0.11.0
networkx>=2.6.0
pyyaml>=6.0
gitpython>=3.1.0
nltk>=3.6.0
wordcloud>=1.8.0
toml>=0.10.0
requests>=2.27.0
```

4. Download NLTK data:
```python
import nltk
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
```

## Usage

### Basic Usage

Run the complete analysis with default settings:

```bash
python main.py
```

This will:
1. Clone the repositories
2. Collect all rules
3. Perform clustering analysis
4. Analyze rule similarities
5. Categorize rules
6. Generate a summary report

### Customized Analysis

You can customize various aspects of the analysis:

```bash
python main.py --output ./my_analysis --n-clusters 40 --n-topics 20 --similarity-threshold 0.75
```

### Skip Steps

If you've already performed certain steps, you can skip them:

```bash
# Skip repository cloning
python main.py --skip-clone

# Skip rule collection (use previously collected rules)
python main.py --skip-clone --skip-collect

# Skip similarity analysis
python main.py --skip-similarity
```

## Output Structure

The analysis results are organized in the following directory structure:

```
security_rule_analysis/
├── config.json                     # Analysis configuration
├── summary_report.json             # Summary of all analyses in JSON format
├── summary_report.txt              # Human-readable summary report
├── rules/
│   ├── all_rules.csv               # All collected rules
│   └── statistics.json             # Basic statistics about the rules
├── clustering/
│   ├── cluster_summary.json        # Summary of clustering results
│   ├── all_rules.csv               # Rules with cluster assignments
│   └── cluster_X.csv               # Rules in each cluster
├── similarity/
│   ├── group_analysis.json         # Analysis of similar rule groups
│   ├── rules_with_groups.csv       # Rules with group assignments
│   ├── similarity_matrix.npy       # Similarity matrix (NumPy format)
│   ├── similarity_network.png      # Network visualization of similarities
│   ├── similarity_heatmap.png      # Heatmap of rule similarities
│   ├── tsne_projection.png         # t-SNE projection of rules
│   └── group_X/                    # Detailed info for each group
│       ├── rules.csv               # Rules in this group
│       └── summary.json            # Group summary information
└── categorization/
    ├── categorized_rules.csv       # Rules with topic assignments
    ├── topics_info.json            # Topic modeling results
    ├── mitre_mapping.json          # MITRE ATT&CK framework mapping
    ├── detection_patterns.json     # Common detection patterns
    ├── topics/
    │   ├── topic_X_wordcloud.png   # Word cloud for each topic
    │   ├── topic_distribution_by_source.png
    │   ├── topic_strengths_heatmap.png
    │   └── rules/                  # Rules per topic
    └── mitre/
        ├── mitre_tactics_distribution.png
        ├── mitre_techniques_distribution.png
        ├── mitre_tactics_by_source.png
        └── rules/                  # Rules per MITRE tactic
```

## Advanced Configuration

### Adding New Rule Sources

You can extend the toolkit to analyze additional rule sources by modifying the `REPOS` dictionary in `rule_analyzer.py`:

```python
REPOS = {
    'sigma': {
        'url': 'https://github.com/SigmaHQ/sigma.git',
        'rules_path': 'rules/windows',
        'format': 'yaml'
    },
    'splunk': {
        'url': 'https://github.com/splunk/security_content.git',
        'rules_path': 'detections/endpoint',
        'format': 'yaml'
    },
    'elastic': {
        'url': 'https://github.com/elastic/detection-rules.git',
        'rules_path': 'rules/windows',
        'format': 'toml'
    },
    # Add your new source here
    'new_source': {
        'url': 'https://github.com/example/rules.git',
        'rules_path': 'path/to/rules',
        'format': 'yaml'  # or 'toml', 'json', etc.
    }
}
```

You may also need to implement a custom parser method in the `RuleAnalyzer` class if the new source uses a different format.

### Customizing Similarity Metrics

You can adjust how rule similarity is calculated by modifying the `prepare_data` method in `RuleSimilarityAnalyzer`:

```python
def prepare_data(self):
    # Adjust field weights to emphasize different aspects
    self.df['weighted_text'] = (
        self.df['processed_title'] * 3 +  # Give title more weight
        self.df['processed_description'] * 2 +  # Medium weight to description
        self.df['processed_detection']  # Normal weight to detection logic
    )
    
    # Customize TF-IDF parameters
    self.vectorizer = TfidfVectorizer(
        max_features=3000,  # Increase for more detailed analysis
        stop_words='english',
        min_df=3,  # Minimum document frequency
        max_df=0.9,  # Maximum document frequency
        ngram_range=(1, 2)  # Include bigrams
    )
    
    # Transform and return
    self.tfidf_matrix = self.vectorizer.fit_transform(self.df['weighted_text'])
    return self.tfidf_matrix
```

### Tuning Clustering Parameters

For better clustering results, you can experiment with different parameters:

```bash
# Try different numbers of clusters
python main.py --n-clusters 20
python main.py --n-clusters 50

# Adjust similarity threshold
python main.py --similarity-threshold 0.65  # More inclusive groups
python main.py --similarity-threshold 0.85  # Stricter grouping
```

## Troubleshooting

### Common Issues

#### Repository Cloning Errors

If you encounter errors cloning repositories:

```
# Use an existing local copy
python main.py --repo-dir /path/to/existing/repos --skip-clone

# Or clone manually and then run
git clone https://github.com/SigmaHQ/sigma.git ./rule_repos/sigma
git clone https://github.com/splunk/security_content.git ./rule_repos/splunk
git clone https://github.com/elastic/detection-rules.git ./rule_repos/elastic
python main.py --skip-clone
```

#### Memory Issues with Large Datasets

For large rule sets, you might encounter memory errors:

```
# Reduce the features to save memory
# Edit in rule_similarity.py:
self.vectorizer = TfidfVectorizer(max_features=1000)  # Reduce from 2000

# Process repositories separately
python main.py --output ./sigma_analysis --repo-dir ./sigma_only
```

#### Missing Dependencies

If you get import errors:

```bash
pip install -r requirements.txt
pip install nltk wordcloud networkx toml
```

For visualization issues:
```bash
pip install matplotlib seaborn
```

### Getting Help

If you encounter issues or have questions:
1. Check the documentation in the code files
2. Look for error messages in the console output
3. Try running with fewer repositories or a smaller subset of rules

usage: main.py [-h] [--output OUTPUT] [--repo-dir REPO_DIR] [--n-clusters N_CLUSTERS]
               [--n-topics N_TOPICS] [--similarity-threshold SIMILARITY_THRESHOLD]
               [--skip-clone] [--skip-collect] [--skip-similarity] [--skip-categorization]

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT       Output directory for analysis results
  --repo-dir REPO_DIR   Directory for cloning repositories
  --n-clusters N_CLUSTERS
                        Number of clusters for k-means
  --n-topics N_TOPICS   Number of topics for topic modeling
  --similarity-threshold SIMILARITY_THRESHOLD
                        Similarity threshold for grouping
  --skip-clone          Skip cloning repositories
  --skip-collect        Skip collecting rules
  --skip-similarity     Skip similarity analysis
  --skip-categorization Skip categorization analysis
