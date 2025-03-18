import os
import json
import yaml
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
import networkx as nx
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import re
import nltk

# Download NLTK resources
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')

class RuleSimilarityAnalyzer:
    def __init__(self, rules_df):
        self.df = rules_df
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        self.vectorizer = None
        self.tfidf_matrix = None
        self.similarity_matrix = None
        
    def preprocess_text(self, text):
        """Preprocess text for better similarity detection."""
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters
        text = re.sub(r'[^\w\s]', ' ', text)
        
        # Tokenize
        tokens = word_tokenize(text)
        
        # Remove stopwords and lemmatize
        tokens = [self.lemmatizer.lemmatize(word) for word in tokens if word not in self.stop_words]
        
        return ' '.join(tokens)
    
    def prepare_data(self):
        """Prepare the data for similarity analysis."""
        # Preprocess text fields
        self.df['processed_title'] = self.df['title'].fillna('').apply(self.preprocess_text)
        self.df['processed_description'] = self.df['description'].fillna('').apply(self.preprocess_text)
        self.df['processed_detection'] = self.df['detection'].fillna('').apply(self.preprocess_text)
        
        # Create combined text with different weights
        self.df['weighted_text'] = (
            self.df['processed_title'] + ' ' + 
            self.df['processed_title'] + ' ' +  # Duplicate to give more weight
            self.df['processed_description'] + ' ' + 
            self.df['processed_detection']
        )
        
        # Create vectorizer and transform
        self.vectorizer = TfidfVectorizer(max_features=2000)
        self.tfidf_matrix = self.vectorizer.fit_transform(self.df['weighted_text'])
        
        return self.tfidf_matrix
    
    def compute_similarity_matrix(self):
        """Compute similarity matrix between all rules."""
        if self.tfidf_matrix is None:
            self.prepare_data()
            
        # Compute cosine similarity
        self.similarity_matrix = cosine_similarity(self.tfidf_matrix)
        
        return self.similarity_matrix
    
    def get_similar_rules(self, rule_idx, threshold=0.6):
        """Get rules similar to a specific rule."""
        if self.similarity_matrix is None:
            self.compute_similarity_matrix()
            
        similarities = self.similarity_matrix[rule_idx]
        similar_indices = [i for i, sim in enumerate(similarities) 
                          if sim >= threshold and i != rule_idx]
        
        similar_rules = self.df.iloc[similar_indices].copy()
        similar_rules['similarity_score'] = [similarities[i] for i in similar_indices]
        
        return similar_rules.sort_values('similarity_score', ascending=False)
    
    def identify_rule_groups(self, threshold=0.7):
        """Identify groups of similar rules."""
        if self.similarity_matrix is None:
            self.compute_similarity_matrix()
            
        n_rules = len(self.df)
        groups = []
        processed_indices = set()
        
        for i in range(n_rules):
            if i in processed_indices:
                continue
                
            similarities = self.similarity_matrix[i]
            similar_indices = [j for j, sim in enumerate(similarities) 
                              if sim >= threshold and i != j]
            
            if similar_indices:
                group = [i] + similar_indices
                groups.append(group)
                processed_indices.update(group)
            
        # Create a mapping of rules to groups
        rule_to_group = {}
        for group_idx, group in enumerate(groups):
            for rule_idx in group:
                rule_to_group[rule_idx] = group_idx
                
        # Add group assignment to dataframe
        self.df['group_id'] = self.df.index.map(
            lambda idx: rule_to_group.get(idx, -1)
        )
        
        return groups, rule_to_group
    
    def analyze_groups(self, groups):
        """Analyze the identified groups."""
        group_analysis = []
        
        for group_idx, indices in enumerate(groups):
            group_rules = self.df.iloc[indices]
            
            # Count sources in this group
            source_counts = group_rules['source'].value_counts().to_dict()
            
            # Get all tags
            all_tags = [tag for tags_list in group_rules['tags'] for tag in tags_list if tags_list]
            tag_counts = pd.Series(all_tags).value_counts().head(10).to_dict()
            
            # Extract common terms from titles
            titles = ' '.join(group_rules['processed_title'])
            title_tokens = titles.split()
            title_counts = pd.Series(title_tokens).value_counts().head(10).to_dict()
            
            group_analysis.append({
                'group_id': group_idx,
                'size': len(indices),
                'source_distribution': source_counts,
                'common_tags': tag_counts,
                'common_title_terms': title_counts,
                'rule_ids': group_rules['id'].tolist(),
                'rule_titles': group_rules['title'].tolist(),
                'rule_indices': indices
            })
            
        return group_analysis
    
    def visualize_similarity_network(self, threshold=0.7, output_path='similarity_network.png'):
        """Create a network visualization of rule similarities."""
        if self.similarity_matrix is None:
            self.compute_similarity_matrix()
            
        # Create a graph
        G = nx.Graph()
        
        # Add nodes (rules)
        for idx, row in self.df.iterrows():
            G.add_node(idx, title=row['title'], source=row['source'])
            
        # Add edges (similarities above threshold)
        n_rules = len(self.df)
        for i in range(n_rules):
            for j in range(i+1, n_rules):
                similarity = self.similarity_matrix[i, j]
                if similarity >= threshold:
                    G.add_edge(i, j, weight=similarity)
        
        # Plot
        plt.figure(figsize=(20, 20))
        
        # Use different colors for different sources
        source_colors = {'sigma': 'blue', 'splunk': 'green', 'elastic': 'red'}
        node_colors = [source_colors[self.df.iloc[node]['source']] for node in G.nodes()]
        
        # Draw the network
        pos = nx.spring_layout(G, k=0.15, iterations=50)
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=50, alpha=0.8)
        nx.draw_networkx_edges(G, pos, alpha=0.1)
        
        # Add a legend
        for source, color in source_colors.items():
            plt.scatter([], [], c=color, label=source)
            
        plt.legend(scatterpoints=1, fontsize=12)
        plt.title('Rule Similarity Network', fontsize=20)
        plt.axis('off')
        
        # Save the figure
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return G
    
    def visualize_similarity_heatmap(self, sample_size=100, output_path='similarity_heatmap.png'):
        """Create a heatmap visualization of rule similarities."""
        if self.similarity_matrix is None:
            self.compute_similarity_matrix()
            
        # Take a sample if dataset is large
        if len(self.df) > sample_size:
            sample_indices = np.random.choice(len(self.df), sample_size, replace=False)
            sample_matrix = self.similarity_matrix[np.ix_(sample_indices, sample_indices)]
            sample_df = self.df.iloc[sample_indices]
        else:
            sample_matrix = self.similarity_matrix
            sample_df = self.df
            
        # Create labels
        labels = [f"{idx}: {row['source']} - {row['title'][:20]}..." 
                 for idx, row in sample_df.iterrows()]
            
        # Plot heatmap
        plt.figure(figsize=(20, 20))
        sns.heatmap(sample_matrix, xticklabels=False, yticklabels=False, cmap='viridis')
        plt.title('Rule Similarity Heatmap', fontsize=20)
        
        # Save the figure
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
    def visualize_tsne_projection(self, output_path='tsne_projection.png'):
        """Create a t-SNE projection of rules."""
        if self.tfidf_matrix is None:
            self.prepare_data()
            
        # Apply t-SNE
        tsne = TSNE(n_components=2, random_state=42, perplexity=30)
        embeddings = tsne.fit_transform(self.tfidf_matrix.toarray())
        
        # Plot
        plt.figure(figsize=(20, 15))
        
        # Use different colors for different sources
        source_colors = {'sigma': 'blue', 'splunk': 'green', 'elastic': 'red'}
        colors = [source_colors[source] for source in self.df['source']]
        
        # Add group coloring if available
        if 'group_id' in self.df.columns:
            # Create a categorical colormap for groups
            unique_groups = self.df['group_id'].unique()
            cmap = plt.cm.get_cmap('tab20', len(unique_groups))
            
            # Plot points with both source shape and group color
            for source, marker in [('sigma', 'o'), ('splunk', 's'), ('elastic', '^')]:
                source_mask = self.df['source'] == source
                for group_id in unique_groups:
                    group_mask = self.df['group_id'] == group_id
                    mask = source_mask & group_mask
                    if any(mask):
                        plt.scatter(
                            embeddings[mask, 0], 
                            embeddings[mask, 1],
                            c=[cmap(int(group_id)) if group_id >= 0 else 'gray'],
                            marker=marker,
                            s=100,
                            alpha=0.7,
                            label=f"{source} - Group {group_id}" if group_id >= 0 else f"{source} - Ungrouped"
                        )
        else:
            # Plot by source only
            for source, color, marker in [('sigma', 'blue', 'o'), ('splunk', 'green', 's'), ('elastic', 'red', '^')]:
                mask = self.df['source'] == source
                plt.scatter(
                    embeddings[mask, 0], 
                    embeddings[mask, 1],
                    c=color,
                    marker=marker,
                    s=100,
                    alpha=0.7,
                    label=source
                )
                
        plt.title('t-SNE Projection of Rules', fontsize=20)
        plt.legend(loc='best')
        
        # Save the figure
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return embeddings
    
    def save_analysis_results(self, output_dir='rule_similarity_analysis'):
        """Save all analysis results."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Identify rule groups
        groups, rule_to_group = self.identify_rule_groups()
        
        # Analyze groups
        group_analysis = self.analyze_groups(groups)
        
        # Save group analysis
        with open(os.path.join(output_dir, 'group_analysis.json'), 'w') as f:
            json.dump(group_analysis, f, indent=2)
            
        # Save similarity matrix
        if self.similarity_matrix is not None:
            np.save(os.path.join(output_dir, 'similarity_matrix.npy'), self.similarity_matrix)
            
        # Save dataframe with group assignments
        self.df.to_csv(os.path.join(output_dir, 'rules_with_groups.csv'), index=False)
        
        # Create visualizations
        self.visualize_similarity_network(output_path=os.path.join(output_dir, 'similarity_network.png'))
        self.visualize_similarity_heatmap(output_path=os.path.join(output_dir, 'similarity_heatmap.png'))
        self.visualize_tsne_projection(output_path=os.path.join(output_dir, 'tsne_projection.png'))
        
        # Save individual rule groups
        for group_id, group_info in enumerate(group_analysis):
            group_rules = self.df.iloc[group_info['rule_indices']]
            
            # Create folder for this group
            group_dir = os.path.join(output_dir, f'group_{group_id}')
            os.makedirs(group_dir, exist_ok=True)
            
            # Save rules in this group
            group_rules.to_csv(os.path.join(group_dir, 'rules.csv'), index=False)
            
            # Save summary information
            with open(os.path.join(group_dir, 'summary.json'), 'w') as f:
                json.dump(group_info, f, indent=2)
                
        print(f"Analysis results saved to {output_dir}")
        
    def generate_group_labels(self, groups, group_analysis):
        """Generate descriptive labels for each group."""
        labels = {}
        
        for group_info in group_analysis:
            group_id = group_info['group_id']
            
            # Combine common title terms and tags
            common_terms = list(group_info['common_title_terms'].keys())
            common_tags = list(group_info['common_tags'].keys())
            
            # Remove common generic terms
            generic_terms = ['windows', 'process', 'event', 'detection']
            terms = [term for term in common_terms if term not in generic_terms][:3]
            
            # Generate a label
            if terms:
                label = ' '.join(terms).title()
            else:
                # Fall back to first rule title
                label = group_info['rule_titles'][0][:30]
                
            labels[group_id] = label
            
        return labels

# Example usage:
# analyzer = RuleSimilarityAnalyzer(rules_df)
# analyzer.prepare_data()
# analyzer.compute_similarity_matrix()
# analyzer.save_analysis_results()
