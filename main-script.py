import os
import sys
import json
import pandas as pd
import argparse
from datetime import datetime

# Import the modules we created
from rule_analyzer import RuleAnalyzer
from rule_similarity import RuleSimilarityAnalyzer
from rule_categorizer import RuleCategorizer

def main():
    """Main function to run the complete analysis."""
    parser = argparse.ArgumentParser(description='Analyze and group security rules.')
    parser.add_argument('--output', default='./security_rule_analysis', help='Output directory for analysis results')
    parser.add_argument('--repo-dir', default='./rule_repos', help='Directory for cloning repositories')
    parser.add_argument('--n-clusters', type=int, default=30, help='Number of clusters for k-means')
    parser.add_argument('--n-topics', type=int, default=15, help='Number of topics for topic modeling')
    parser.add_argument('--similarity-threshold', type=float, default=0.7, help='Similarity threshold for grouping')
    parser.add_argument('--skip-clone', action='store_true', help='Skip cloning repositories')
    parser.add_argument('--skip-collect', action='store_true', help='Skip collecting rules')
    parser.add_argument('--skip-similarity', action='store_true', help='Skip similarity analysis')
    parser.add_argument('--skip-categorization', action='store_true', help='Skip categorization analysis')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Save run configuration
    with open(os.path.join(args.output, 'config.json'), 'w') as f:
        json.dump(vars(args), f, indent=2)
        
    # Step 1: Initialize the rule analyzer
    print("\n=== Step 1: Initialize Rule Analyzer ===")
    analyzer = RuleAnalyzer(base_dir=args.repo_dir)
    
    # Step 2: Clone repositories
    if not args.skip_clone:
        print("\n=== Step 2: Cloning Repositories ===")
        analyzer.clone_repos()
    else:
        print("\n=== Step 2: Skipping Repository Cloning ===")
        
    # Step 3: Collect rules
    if not args.skip_collect:
        print("\n=== Step 3: Collecting Rules ===")
        analyzer.collect_rules()
        analyzer.create_dataframe()
        
        # Save the rules
        rules_dir = os.path.join(args.output, 'rules')
        os.makedirs(rules_dir, exist_ok=True)
        analyzer.df.to_csv(os.path.join(rules_dir, 'all_rules.csv'), index=False)
        
        # Save rule statistics
        stats = {
            'total_rules': len(analyzer.df),
            'rules_by_source': analyzer.df['source'].value_counts().to_dict(),
            'unique_tags': len(set(tag for tags in analyzer.df['tags'] for tag in tags)),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(os.path.join(rules_dir, 'statistics.json'), 'w') as f:
            json.dump(stats, f, indent=2)
    else:
        print("\n=== Step 3: Skipping Rule Collection ===")
        # Load previously collected rules
        rules_path = os.path.join(args.output, 'rules', 'all_rules.csv')
        if os.path.exists(rules_path):
            analyzer.df = pd.read_csv(rules_path)
            print(f"Loaded {len(analyzer.df)} rules from {rules_path}")
        else:
            print("No previously collected rules found. Please run without --skip-collect first.")
            return
    
    # Step 4: Cluster rules
    print("\n=== Step 4: Clustering Rules ===")
    cluster_terms = analyzer.cluster_rules(n_clusters=args.n_clusters)
    analyzer.save_results(output_dir=os.path.join(args.output, 'clustering'))
    
    # Print cluster terms
    for cluster_id, terms in cluster_terms.items():
        print(f"Cluster {cluster_id}: {', '.join(terms)}")
        
    # Step 5: Similarity analysis
    if not args.skip_similarity:
        print("\n=== Step 5: Similarity Analysis ===")
        similarity_analyzer = RuleSimilarityAnalyzer(analyzer.df)
        similarity_analyzer.prepare_data()
        similarity_analyzer.compute_similarity_matrix()
        similarity_analyzer.identify_rule_groups(threshold=args.similarity_threshold)
        similarity_analyzer.save_analysis_results(output_dir=os.path.join(args.output, 'similarity'))
    else:
        print("\n=== Step 5: Skipping Similarity Analysis ===")
        
    # Step 6: Rule categorization
    if not args.skip_categorization:
        print("\n=== Step 6: Rule Categorization ===")
        categorizer = RuleCategorizer(analyzer.df)
        categorizer.extract_mitre_info()
        categorizer.extract_topics(n_topics=args.n_topics)
        categorizer.save_categorization_results(output_dir=os.path.join(args.output, 'categorization'))
    else:
        print("\n=== Step 6: Skipping Rule Categorization ===")
        
    # Step 7: Generate summary report
    print("\n=== Step 7: Generating Summary Report ===")
    generate_summary_report(args.output)
    
    print("\n=== Analysis Complete! ===")
    print(f"Results saved to {args.output}")

def generate_summary_report(output_dir):
    """Generate a summary report of all analysis results."""
    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'sections': []
    }
    
    # Rule statistics
    stats_path = os.path.join(output_dir, 'rules', 'statistics.json')
    if os.path.exists(stats_path):
        with open(stats_path, 'r') as f:
            rule_stats = json.load(f)
            
        report['sections'].append({
            'title': 'Rule Statistics',
            'content': rule_stats
        })
        
    # Clustering results
    cluster_summary_path = os.path.join(output_dir, 'clustering', 'cluster_summary.json')
    if os.path.exists(cluster_summary_path):
        with open(cluster_summary_path, 'r') as f:
            cluster_summary = json.load(f)
            
        report['sections'].append({
            'title': 'Clustering Results',
            'content': {
                'num_clusters': len(cluster_summary['cluster_counts']),
                'cluster_sizes': cluster_summary['cluster_counts'],
                'source_distribution': cluster_summary['source_distribution']
            }
        })
        
    # Similarity groups
    similarity_path = os.path.join(output_dir, 'similarity', 'group_analysis.json')
    if os.path.exists(similarity_path):
        with open(similarity_path, 'r') as f:
            similarity_analysis = json.load(f)
            
        report['sections'].append({
            'title': 'Similarity Analysis',
            'content': {
                'num_groups': len(similarity_analysis),
                'total_grouped_rules': sum(group['size'] for group in similarity_analysis),
                'largest_groups': sorted(similarity_analysis, key=lambda x: x['size'], reverse=True)[:5]
            }
        })
        
    # Topic analysis
    topics_path = os.path.join(output_dir, 'categorization', 'topics_info.json')
    if os.path.exists(topics_path):
        with open(topics_path, 'r') as f:
            topics_info = json.load(f)
            
        report['sections'].append({
            'title': 'Topic Analysis',
            'content': {
                'num_topics': len(topics_info['topic_labels']),
                'topics': topics_info['topic_labels'],
                'topic_counts': topics_info['topic_counts']
            }
        })
        
    # MITRE analysis
    mitre_path = os.path.join(output_dir, 'categorization', 'mitre_mapping.json')
    if os.path.exists(mitre_path):
        with open(mitre_path, 'r') as f:
            mitre_mapping = json.load(f)
            
        # Get top 10 tactics and techniques
        tactics = sorted(mitre_mapping['tactics'].items(), key=lambda x: x[1], reverse=True)[:10]
        techniques = sorted(mitre_mapping['techniques'].items(), key=lambda x: x[1], reverse=True)[:10]
            
        report['sections'].append({
            'title': 'MITRE ATT&CK Analysis',
            'content': {
                'num_tactics': len(mitre_mapping['tactics']),
                'num_techniques': len(mitre_mapping['techniques']),
                'top_tactics': dict(tactics),
                'top_techniques': dict(techniques)
            }
        })
        
    # Save the report
    with open(os.path.join(output_dir, 'summary_report.json'), 'w') as f:
        json.dump(report, f, indent=2)
        
    # Also generate a text version
    with open(os.path.join(output_dir, 'summary_report.txt'), 'w') as f:
        f.write("SECURITY RULE ANALYSIS SUMMARY\n")
        f.write("==============================\n\n")
        f.write(f"Generated on: {report['timestamp']}\n\n")
        
        for section in report['sections']:
            f.write(f"## {section['title']}\n")
            f.write("-------------------\n\n")
            
            if section['title'] == 'Rule Statistics':
                content = section['content']
                f.write(f"Total Rules: {content['total_rules']}\n")
                f.write("Rules by Source:\n")
                for source, count in content['rules_by_source'].items():
                    f.write(f"  - {source}: {count}\n")
                f.write(f"Unique Tags: {content['unique_tags']}\n\n")
                
            elif section['title'] == 'Clustering Results':
                content = section['content']
                f.write(f"Number of Clusters: {content['num_clusters']}\n")
                f.write("Largest Clusters:\n")
                
                largest = sorted(content['cluster_sizes'].items(), key=lambda x: int(x[1]), reverse=True)[:5]
                for cluster_id, size in largest:
                    f.write(f"  - Cluster {cluster_id}: {size} rules\n")
                f.write("\n")
                
            elif section['title'] == 'Similarity Analysis':
                content = section['content']
                f.write(f"Number of Similar Rule Groups: {content['num_groups']}\n")
                f.write(f"Total Rules in Groups: {content['total_grouped_rules']}\n")
                f.write("Largest Groups:\n")
                
                for i, group in enumerate(content['largest_groups']):
                    f.write(f"  - Group {group['group_id']}: {group['size']} rules\n")
                    f.write(f"    Common tags: {', '.join(list(group['common_tags'].keys())[:3])}\n")
                f.write("\n")
                
            elif section['title'] == 'Topic Analysis':
                content = section['content']
                f.write(f"Number of Topics: {content['num_topics']}\n")
                f.write("Topics:\n")
                
                for topic_id, label in content['topics'].items():
                    count = content['topic_counts'][topic_id]
                    f.write(f"  - Topic {topic_id} ({count} rules): {label}\n")
                f.write("\n")
                
            elif section['title'] == 'MITRE ATT&CK Analysis':
                content = section['content']
                f.write(f"Number of Tactics: {content['num_tactics']}\n")
                f.write(f"Number of Techniques: {content['num_techniques']}\n")
                
                f.write("Top Tactics:\n")
                for tactic, count in content['top_tactics'].items():
                    f.write(f"  - {tactic}: {count} rules\n")
                    
                f.write("\nTop Techniques:\n")
                for technique, count in content['top_techniques'].items():
                    f.write(f"  - {technique}: {count} rules\n")
                f.write("\n")

if __name__ == "__main__":
    main()
