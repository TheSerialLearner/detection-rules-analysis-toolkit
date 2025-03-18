import os
import json
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import NMF, LatentDirichletAllocation
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
from wordcloud import WordCloud
import re

class RuleCategorizer:
    def __init__(self, rules_df):
        self.df = rules_df
        self.topic_model = None
        self.vectorizer = None
        self.doc_topic_matrix = None
        self.topic_keywords = None
        self.mitre_mapping = None
        
    def extract_mitre_info(self):
        """Extract MITRE ATT&CK information from tags."""
        # Initialize columns
        self.df['mitre_tactics'] = self.df['tags'].apply(lambda x: [] if not x else x)
        self.df['mitre_techniques'] = self.df['tags'].apply(lambda x: [] if not x else x)
        
        # Extract tactics and techniques
        tactic_pattern = re.compile(r'attack\.tactic\.([a-z_]+)', re.IGNORECASE)
        technique_pattern = re.compile(r'attack\.t\d+(?:\.\d+)?', re.IGNORECASE)
        
        for idx, tags in enumerate(self.df['tags']):
            if not tags:
                continue
                
            tactics = []
            techniques = []
            
            for tag in tags:
                tag_str = str(tag).lower()
                
                # Look for tactics
                tactic_match = tactic_pattern.search(tag_str)
                if tactic_match:
                    tactics.append(tactic_match.group(1))
                    
                # Look for techniques
                technique_match = technique_pattern.search(tag_str)
                if technique_match:
                    techniques.append(technique_match.group(0))
            
            self.df.at[idx, 'mitre_tactics'] = tactics
            self.df.at[idx, 'mitre_techniques'] = techniques
            
        # Create a mapping of MITRE ATT&CK IDs to rule counts
        tactic_counts = Counter()
        technique_counts = Counter()
        
        for tactics in self.df['mitre_tactics']:
            tactic_counts.update(tactics)
            
        for techniques in self.df['mitre_techniques']:
            technique_counts.update(techniques)
            
        self.mitre_mapping = {
            'tactics': dict(tactic_counts),
            'techniques': dict(technique_counts)
        }
        
        return self.mitre_mapping
    
    def analyze_rule_content(self):
        """Analyze rule content to extract common patterns."""
        # Analyze detection patterns
        detection_patterns = {}
        
        # Look for common Windows event IDs
        event_id_pattern = re.compile(r'event_?id\s*[=:]\s*(\d+)', re.IGNORECASE)
        event_ids = []
        
        for detection in self.df['detection']:
            if not isinstance(detection, str):
                continue
                
            matches = event_id_pattern.findall(detection)
            event_ids.extend(matches)
            
        detection_patterns['event_ids'] = Counter(event_ids)
        
        # Look for common registry keys
        registry_pattern = re.compile(r'HKEY_[A-Z_\\]+', re.IGNORECASE)
        registry_keys = []
        
        for detection in self.df['detection']:
            if not isinstance(detection, str):
                continue
                
            matches = registry_pattern.findall(detection)
            registry_keys.extend(matches)
            
        detection_patterns['registry_keys'] = Counter(registry_keys)
        
        # Look for common file paths
        file_path_pattern = re.compile(r'\\[A-Za-z0-9\\_.]+\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js)', re.IGNORECASE)
        file_paths = []
        
        for detection in self.df['detection']:
            if not isinstance(detection, str):
                continue
                
            matches = file_path_pattern.findall(detection)
            file_paths.extend(matches)
            
        detection_patterns['file_paths'] = Counter(file_paths)
        
        return detection_patterns
        
    def extract_topics(self, n_topics=15, n_top_words=10):
        """Extract topics from rule descriptions using NMF."""
        # Prepare text
        descriptions = self.df['description'].fillna('').astype(str)
        
        # Create vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=2000, 
            stop_words='english',
            min_df=5,
            max_df=0.9
        )
        
        # Transform text to tf-idf matrix
        tfidf_matrix = self.vectorizer.fit_transform(descriptions)
        
        # Apply Non-negative Matrix Factorization
        self.topic_model = NMF(n_components=n_topics, random_state=42)
        self.doc_topic_matrix = self.topic_model.fit_transform(tfidf_matrix)
        
        # Get feature names
        feature_names = self.vectorizer.get_feature_names_out()
        
        # Extract top words for each topic
        self.topic_keywords = []
        for topic_idx, topic in enumerate(self.topic_model.components_):
            top_keywords_idx = topic.argsort()[:-n_top_words-1:-1]
            top_keywords = [feature_names[i] for i in top_keywords_idx]
            self.topic_keywords.append(top_keywords)
            
        # Assign topics to rules
        topic_assignments = np.argmax(self.doc_topic_matrix, axis=1)
        self.df['topic_id'] = topic_assignments
        self.df['topic_score'] = np.max(self.doc_topic_matrix, axis=1)
        
        # Create topic labels
        topic_labels = []
        for keywords in self.topic_keywords:
            label = ' '.join(keywords[:3]).title()
            topic_labels.append(label)
            
        # Topic info dictionary
        topics_info = {
            'topic_keywords': {i: keywords for i, keywords in enumerate(self.topic_keywords)},
            'topic_labels': {i: label for i, label in enumerate(topic_labels)},
            'topic_counts': {i: int((topic_assignments == i).sum()) for i in range(n_topics)}
        }
        
        return topics_info
    
    def visualize_topics(self, output_dir='topic_analysis'):
        """Create visualizations for topic analysis."""
        if self.topic_keywords is None:
            print("Run extract_topics first")
            return
            
        os.makedirs(output_dir, exist_ok=True)
        
        # Create word clouds for each topic
        for topic_idx, keywords in enumerate(self.topic_keywords):
            # Generate text for wordcloud
            text = ' '.join(keywords)
            
            # Create wordcloud
            wordcloud = WordCloud(
                width=800, 
                height=400, 
                background_color='white',
                max_words=100
            ).generate(text)
            
            # Plot wordcloud
            plt.figure(figsize=(10, 5))
            plt.imshow(wordcloud, interpolation='bilinear')
            plt.axis('off')
            plt.title(f'Topic {topic_idx}')
            
            # Save figure
            plt.savefig(os.path.join(output_dir, f'topic_{topic_idx}_wordcloud.png'), 
                       dpi=300, bbox_inches='tight')
            plt.close()
            
        # Topic distribution by source
        topic_source_counts = self.df.groupby(['topic_id', 'source']).size().unstack(fill_value=0)
        
        plt.figure(figsize=(15, 8))
        topic_source_counts.plot(kind='bar', stacked=True)
        plt.title('Topic Distribution by Source')
        plt.xlabel('Topic ID')
        plt.ylabel('Number of Rules')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # Save figure
        plt.savefig(os.path.join(output_dir, 'topic_distribution_by_source.png'),
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        # Topic heatmap
        if self.doc_topic_matrix is not None:
            # Create a subset for visualization if matrix is large
            if self.doc_topic_matrix.shape[0] > 200:
                sample_idx = np.random.choice(
                    self.doc_topic_matrix.shape[0], 
                    size=200, 
                    replace=False
                )
                sample_matrix = self.doc_topic_matrix[sample_idx]
            else:
                sample_matrix = self.doc_topic_matrix
                
            plt.figure(figsize=(12, 10))
            sns.heatmap(
                sample_matrix, 
                cmap='viridis',
                xticklabels=range(self.doc_topic_matrix.shape[1]),
                yticklabels=False
            )
            plt.title('Topic Strengths Across Rules')
            plt.xlabel('Topic ID')
            plt.ylabel('Rules')
            
            # Save figure
            plt.savefig(os.path.join(output_dir, 'topic_strengths_heatmap.png'),
                       dpi=300, bbox_inches='tight')
            plt.close()
    
    def visualize_mitre_mapping(self, output_dir='mitre_analysis'):
        """Create visualizations for MITRE ATT&CK mapping."""
        if self.mitre_mapping is None:
            self.extract_mitre_info()
            
        os.makedirs(output_dir, exist_ok=True)
        
        # Tactics visualization
        if self.mitre_mapping['tactics']:
            tactics_df = pd.DataFrame({
                'tactic': list(self.mitre_mapping['tactics'].keys()),
                'count': list(self.mitre_mapping['tactics'].values())
            })
            
            tactics_df = tactics_df.sort_values('count', ascending=False)
            
            plt.figure(figsize=(15, 8))
            sns.barplot(x='tactic', y='count', data=tactics_df)
            plt.title('MITRE ATT&CK Tactics Distribution')
            plt.xlabel('Tactic')
            plt.ylabel('Number of Rules')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            
            # Save figure
            plt.savefig(os.path.join(output_dir, 'mitre_tactics_distribution.png'),
                       dpi=300, bbox_inches='tight')
            plt.close()
            
        # Techniques visualization (top 20)
        if self.mitre_mapping['techniques']:
            techniques_df = pd.DataFrame({
                'technique': list(self.mitre_mapping['techniques'].keys()),
                'count': list(self.mitre_mapping['techniques'].values())
            })
            
            techniques_df = techniques_df.sort_values('count', ascending=False).head(20)
            
            plt.figure(figsize=(15, 8))
            sns.barplot(x='technique', y='count', data=techniques_df)
            plt.title('MITRE ATT&CK Techniques Distribution (Top 20)')
            plt.xlabel('Technique')
            plt.ylabel('Number of Rules')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            
            # Save figure
            plt.savefig(os.path.join(output_dir, 'mitre_techniques_distribution.png'),
                       dpi=300, bbox_inches='tight')
            plt.close()
            
        # Distribution by source
        source_tactics = {}
        
        for _, row in self.df.iterrows():
            source = row['source']
            tactics = row['mitre_tactics']
            
            if source not in source_tactics:
                source_tactics[source] = Counter()
                
            source_tactics[source].update(tactics)
            
        # Create a dataframe for visualization
        tactic_source_data = []
        
        for source, tactic_counter in source_tactics.items():
            for tactic, count in tactic_counter.items():
                tactic_source_data.append({
                    'source': source,
                    'tactic': tactic,
                    'count': count
                })
                
        if tactic_source_data:
            tactic_source_df = pd.DataFrame(tactic_source_data)
            
            # Create a pivot table
            pivot_df = tactic_source_df.pivot_table(
                index='tactic',
                columns='source',
                values='count',
                fill_value=0
            )
            
            plt.figure(figsize=(15, 10))
            sns.heatmap(pivot_df, annot=True, fmt='d', cmap='viridis')
            plt.title('MITRE ATT&CK Tactics by Source')
            plt.tight_layout()
            
            # Save figure
            plt.savefig(os.path.join(output_dir, 'mitre_tactics_by_source.png'),
                       dpi=300, bbox_inches='tight')
            plt.close()
    
    def save_categorization_results(self, output_dir='rule_categorization'):
        """Save all categorization results."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Extract MITRE information
        mitre_mapping = self.extract_mitre_info()
        
        # Extract topics
        topics_info = self.extract_topics()
        
        # Analyze rule content
        detection_patterns = self.analyze_rule_content()
        
        # Save dataframe with categorization
        self.df.to_csv(os.path.join(output_dir, 'categorized_rules.csv'), index=False)
        
        # Save MITRE mapping
        with open(os.path.join(output_dir, 'mitre_mapping.json'), 'w') as f:
            json.dump(mitre_mapping, f, indent=2)
            
        # Save topics info
        with open(os.path.join(output_dir, 'topics_info.json'), 'w') as f:
            json.dump(topics_info, f, indent=2)
            
        # Save detection patterns
        with open(os.path.join(output_dir, 'detection_patterns.json'), 'w') as f:
            detection_patterns_serializable = {
                k: {str(k2): v2 for k2, v2 in v.items()} 
                for k, v in detection_patterns.items()
            }
            json.dump(detection_patterns_serializable, f, indent=2)
            
        # Create visualizations
        self.visualize_topics(os.path.join(output_dir, 'topics'))
        self.visualize_mitre_mapping(os.path.join(output_dir, 'mitre'))
        
        # Generate per-topic rule listings
        os.makedirs(os.path.join(output_dir, 'topics', 'rules'), exist_ok=True)
        
        for topic_id in self.df['topic_id'].unique():
            topic_rules = self.df[self.df['topic_id'] == topic_id]
            topic_rules.to_csv(
                os.path.join(output_dir, 'topics', 'rules', f'topic_{topic_id}_rules.csv'),
                index=False
            )
            
        # Generate per-tactic rule listings
        os.makedirs(os.path.join(output_dir, 'mitre', 'rules'), exist_ok=True)
        
        all_tactics = set()
        for tactics in self.df['mitre_tactics']:
            all_tactics.update(tactics)
            
        for tactic in all_tactics:
            tactic_rules = self.df[self.df['mitre_tactics'].apply(lambda x: tactic in x)]
            tactic_rules.to_csv(
                os.path.join(output_dir, 'mitre', 'rules', f'tactic_{tactic}_rules.csv'),
                index=False
            )
            
        print(f"Categorization results saved to {output_dir}")
