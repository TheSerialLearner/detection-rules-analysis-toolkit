import os
import json
import yaml
import requests
from git import Repo
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics.pairwise import cosine_similarity
import matplotlib.pyplot as plt
from collections import defaultdict

# Configuration
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
        'format': 'toml' # Note: Elastic uses TOML format
    }
}

class RuleAnalyzer:
    def __init__(self, base_dir='./rule_repos'):
        self.base_dir = base_dir
        self.rules = []
        self.df = None
        
    def clone_repos(self):
        """Clone the repositories if they don't exist."""
        os.makedirs(self.base_dir, exist_ok=True)
        
        for repo_name, repo_info in REPOS.items():
            repo_path = os.path.join(self.base_dir, repo_name)
            if not os.path.exists(repo_path):
                print(f"Cloning {repo_name} repository...")
                Repo.clone_from(repo_info['url'], repo_path)
            else:
                print(f"{repo_name} repository already exists.")
    
    def parse_yaml_rule(self, file_path, source):
        """Parse a YAML rule file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                rule_data = yaml.safe_load(f)
                
                # Handle Sigma format
                if source == 'sigma':
                    if isinstance(rule_data, dict):
                        rule = {
                            'source': source,
                            'id': rule_data.get('id', ''),
                            'title': rule_data.get('title', ''),
                            'description': rule_data.get('description', ''),
                            'tags': rule_data.get('tags', []),
                            'detection': str(rule_data.get('detection', {})),
                            'file_path': file_path,
                            'raw': rule_data
                        }
                        return rule
                
                # Handle Splunk format
                elif source == 'splunk':
                    if isinstance(rule_data, dict):
                        rule = {
                            'source': source,
                            'id': rule_data.get('id', ''),
                            'title': rule_data.get('name', ''),
                            'description': rule_data.get('description', ''),
                            'tags': rule_data.get('tags', []),
                            'detection': str(rule_data.get('search', '')),
                            'file_path': file_path,
                            'raw': rule_data
                        }
                        return rule
            except yaml.YAMLError as e:
                print(f"Error parsing YAML in {file_path}: {e}")
        return None
    
    def parse_toml_rule(self, file_path, source):
        """Parse a TOML rule file (for Elastic)."""
        try:
            import toml
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = toml.load(f)
                
                # Handle Elastic format
                rule = {
                    'source': source,
                    'id': rule_data.get('rule', {}).get('id', ''),
                    'title': rule_data.get('rule', {}).get('name', ''),
                    'description': rule_data.get('rule', {}).get('description', ''),
                    'tags': rule_data.get('rule', {}).get('tags', []),
                    'detection': str(rule_data.get('rule', {}).get('query', '')),
                    'file_path': file_path,
                    'raw': rule_data
                }
                return rule
        except Exception as e:
            print(f"Error parsing TOML in {file_path}: {e}")
        return None
    
    def collect_rules(self):
        """Collect rules from all repositories."""
        for repo_name, repo_info in REPOS.items():
            repo_path = os.path.join(self.base_dir, repo_name)
            rules_dir = os.path.join(repo_path, repo_info['rules_path'])
            
            if not os.path.exists(rules_dir):
                print(f"Rules directory not found for {repo_name}")
                continue
                
            print(f"Collecting rules from {repo_name}...")
            for root, _, files in os.walk(rules_dir):
                for file in files:
                    if repo_info['format'] == 'yaml' and file.endswith(('.yml', '.yaml')):
                        file_path = os.path.join(root, file)
                        rule = self.parse_yaml_rule(file_path, repo_name)
                        if rule:
                            self.rules.append(rule)
                            
                    elif repo_info['format'] == 'toml' and file.endswith('.toml'):
                        file_path = os.path.join(root, file)
                        rule = self.parse_toml_rule(file_path, repo_name)
                        if rule:
                            self.rules.append(rule)
        
        print(f"Collected {len(self.rules)} rules in total.")
    
    def create_dataframe(self):
        """Convert rules to a pandas DataFrame."""
        self.df = pd.DataFrame(self.rules)
        
        # Clean up tags
        def flatten_tags(tags):
            if isinstance(tags, list):
                return [str(tag) for tag in tags]
            elif isinstance(tags, dict):
                return [f"{k}:{v}" for k, v in tags.items()]
            else:
                return []
                
        self.df['tags'] = self.df['tags'].apply(flatten_tags)
        
        # Create a combined text field for clustering
        self.df['text_for_clustering'] = self.df['title'] + ' ' + self.df['description'] + ' ' + self.df['detection']
        
        return self.df
    
    def cluster_rules(self, n_clusters=20):
        """Cluster rules based on their text content."""
        if self.df is None:
            self.create_dataframe()
            
        # Vectorize the text
        vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        X = vectorizer.fit_transform(self.df['text_for_clustering'])
        
        # Apply KMeans clustering
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        self.df['cluster'] = kmeans.fit_predict(X)
        
        # Get feature names
        feature_names = vectorizer.get_feature_names_out()
        
        # Get cluster centers
        cluster_centers = kmeans.cluster_centers_
        
        # Extract top terms per cluster
        cluster_terms = {}
        for i in range(n_clusters):
            # Get indices of top 10 terms for this cluster
            indices = cluster_centers[i].argsort()[-10:][::-1]
            top_terms = [feature_names[j] for j in indices]
            cluster_terms[i] = top_terms
            
        return cluster_terms
    
    def find_similar_rules(self, rule_index, threshold=0.6):
        """Find rules similar to a given rule based on text similarity."""
        if self.df is None:
            self.create_dataframe()
            
        # Vectorize the text
        vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        X = vectorizer.fit_transform(self.df['text_for_clustering'])
        
        # Compute cosine similarity
        target_vector = X[rule_index].toarray().reshape(1, -1)
        sim_scores = cosine_similarity(target_vector, X).flatten()
        
        # Get similar rules (excluding the rule itself)
        similar_indices = [i for i, score in enumerate(sim_scores) if score >= threshold and i != rule_index]
        similar_rules = self.df.iloc[similar_indices]
        
        return similar_rules.sort_values(by='source')
    
    def analyze_clusters(self):
        """Analyze the clusters and provide summary statistics."""
        if 'cluster' not in self.df.columns:
            print("Run cluster_rules first.")
            return
            
        # Count rules per cluster
        cluster_counts = self.df['cluster'].value_counts().sort_index()
        
        # Count sources per cluster
        source_distribution = self.df.groupby(['cluster', 'source']).size().unstack(fill_value=0)
        
        # Most common tags per cluster
        cluster_tags = {}
        for cluster_id in self.df['cluster'].unique():
            cluster_rules = self.df[self.df['cluster'] == cluster_id]
            all_tags = [tag for tags_list in cluster_rules['tags'] for tag in tags_list]
            tag_counts = pd.Series(all_tags).value_counts().head(5)
            cluster_tags[cluster_id] = tag_counts.to_dict()
            
        return {
            'cluster_counts': cluster_counts,
            'source_distribution': source_distribution,
            'cluster_tags': cluster_tags
        }
    
    def save_results(self, output_dir='./rule_analysis'):
        """Save analysis results to files."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save the full dataframe
        self.df.to_csv(os.path.join(output_dir, 'all_rules.csv'), index=False)
        
        # Save cluster information
        if 'cluster' in self.df.columns:
            cluster_analysis = self.analyze_clusters()
            
            # Save each cluster as a separate file
            for cluster_id in self.df['cluster'].unique():
                cluster_rules = self.df[self.df['cluster'] == cluster_id]
                cluster_rules.to_csv(os.path.join(output_dir, f'cluster_{cluster_id}.csv'), index=False)
            
            # Save cluster summary
            with open(os.path.join(output_dir, 'cluster_summary.json'), 'w') as f:
                json.dump({
                    'cluster_counts': cluster_analysis['cluster_counts'].to_dict(),
                    'source_distribution': cluster_analysis['source_distribution'].to_dict(),
                    'cluster_tags': cluster_analysis['cluster_tags']
                }, f, indent=2)
                
        print(f"Results saved to {output_dir}")

# Example usage
if __name__ == "__main__":
    analyzer = RuleAnalyzer()
    analyzer.clone_repos()
    analyzer.collect_rules()
    analyzer.create_dataframe()
    
    # Cluster the rules
    cluster_terms = analyzer.cluster_rules(n_clusters=30)
    
    # Print cluster terms
    for cluster_id, terms in cluster_terms.items():
        print(f"Cluster {cluster_id}: {', '.join(terms)}")
    
    # Analyze and save results
    analyzer.save_results()
    
    print("Analysis complete!")
