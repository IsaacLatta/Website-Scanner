#!/usr/bin/env python3
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Dict, List, Optional
import csv

class PlotGenerator:
    def __init__(self, output_dir: Path, output_filename: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.output_filename = output_filename

        plt.style.use('default')
        self.colors = {
            'good': 'green',
            'bad': 'red',
            'warning': 'orange',
            'info': 'lightblue',
            'neutral': 'gray'
        }

    def generate_reports(self, results: Dict, total_domains: int):
        self._write_csv(results)
        
        print("\nGenerating visualizations...")
        
        if 'https_results' in results:
            https_capable = len(results.get('https_capable', []))
            https_failed = total_domains - https_capable
            self.plot_https_connectivity(https_capable, https_failed, total_domains)
        
        if 'headers' in results.get('aggregated', {}):
            header_stats = results['aggregated']['headers']
            self.plot_header_implementation(header_stats)
        
        if 'tls' in results.get('aggregated', {}):
            tls_stats = results['aggregated']['tls']
            self.plot_tls_support(tls_stats)
        
        if 'cipher' in results.get('aggregated', {}):
            cipher_stats = results['aggregated']['cipher']
            self.plot_cipher_security(cipher_stats)
        
        if 'securitytxt' in results.get('aggregated', {}):
            sectxt_stats = results['aggregated']['securitytxt']
            self.plot_securitytxt(sectxt_stats)
        
        if 'redirection' in results.get('aggregated', {}):
            redir_stats = results['aggregated']['redirection']
            self.plot_redirection(redir_stats)
    
    def _write_csv(self, results: Dict):
        csv_path = self.output_dir / self.csv_filename
        
        if not results.get('per_site'):
            print("No results to write to CSV")
            return
        
        all_keys = set()
        for site in results['per_site']:
            all_keys.update(site.keys())
        
        all_keys.discard('response_data')
        
        fieldnames = ['host', 'https_ok'] + sorted([k for k in all_keys if k not in ['host', 'https_ok']])
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for site in results['per_site']:
                row = {}
                for key in fieldnames:
                    value = site.get(key, '')
                    if isinstance(value, bool):
                        row[key] = str(value)
                    elif value is None:
                        row[key] = ''
                    else:
                        row[key] = value
                writer.writerow(row)

    def _save_plot(self, filename: str):
        filepath = self.output_dir / filename
        plt.tight_layout()
        plt.savefig(filepath, dpi=100, bbox_inches='tight')
        plt.clf()
    
    def _add_percentages(self, ax, values):
        for i, v in enumerate(values):
            if v > 0:
                ax.text(i, v, f'{v:.1f}%', ha='center', va='bottom')
    
    def plot_https_connectivity(self, capable: int, failed: int, total: int):
        fig, ax = plt.subplots(figsize=(8, 6))
        
        success_pct = (capable / total) * 100 if total > 0 else 0
        fail_pct = (failed / total) * 100 if total > 0 else 0
        
        labels = ['HTTPS Supported', 'HTTPS Failed']
        values = [success_pct, fail_pct]
        colors = [self.colors['good'], self.colors['bad']]
        
        bars = ax.bar(labels, values, color=colors)
        self._add_percentages(ax, values)
        
        ax.set_ylabel('Percentage (%)')
        ax.set_title(f'HTTPS Connectivity Test Results (n={total})')
        ax.set_ylim(0, 105)
        
        self._save_plot('https_connectivity.png')
    
    def plot_header_implementation(self, stats: Dict):
        if not stats or stats.get('total', 0) == 0:
            return

        total = stats['total']
        headers_data = stats.get('headers', {})
        if not headers_data:
            return

        num_headers = len(headers_data)
        cols = 3
        rows = (num_headers + cols - 1) // cols

        fig, axes = plt.subplots(rows, cols, figsize=(15, rows * 3.5))
        if rows == 1:
            axes = [axes] if cols == 1 else axes
        else:
            axes = axes.flatten()

        for idx, (header_key, header_stats) in enumerate(headers_data.items()):
            if idx >= len(axes):
                break
            ax = axes[idx]
            present = (header_stats['present'] / total) * 100 if total > 0 else 0
            absent = 100 - present

            ax.bar(['Present', 'Absent'], [present, absent],
                color=[self.colors['good'], self.colors['bad']])
            ax.set_title(header_stats.get('display_name', header_key))
            ax.set_ylabel('Percentage (%)')
            self._add_percentages(ax, [present, absent])
            ax.set_ylim(0, 105)

        for idx in range(len(headers_data), len(axes)):
            axes[idx].set_visible(False)

        plt.suptitle(f'Security Headers Implementation (n={total})', fontsize=16)
        self._save_plot('security_headers.png')

        self._plot_header_correctness(stats)

        rev = stats.get('revealing_headers', {})
        if rev and total > 0:
            fig, ax = plt.subplots(figsize=(7, 5))
            revealing = (rev.get('count', 0) / total) * 100
            not_revealing = 100 - revealing
            ax.bar(['Has Revealing', 'No Revealing'],
                [revealing, not_revealing],
                color=[self.colors['bad'], self.colors['good']])
            self._add_percentages(ax, [revealing, not_revealing])
            ax.set_ylabel('Percentage (%)')
            ax.set_title('Information Revealing Headers')
            ax.set_ylim(0, 105)
            self._save_plot('revealing_headers.png')

        if stats.get('custom_missing') or stats.get('custom_regex'):
            self._plot_custom_headers(stats)

    def _plot_header_correctness(self, stats: Dict):
        """Plot correctness of implemented headers (values under stats['headers'])."""
        if not stats or stats.get('total', 0) == 0:
            return

        headers_data = stats.get('headers', {})
        if not headers_data:
            return

        headers_with_validation = [(k, v) for k, v in headers_data.items()
                                if v['present'] > 0 and 'correct' in v]

        if not headers_with_validation:
            return

        num_headers = len(headers_with_validation)
        cols = 3
        rows = (num_headers + cols - 1) // cols

        fig, axes = plt.subplots(rows, cols, figsize=(15, rows * 3.5))
        if rows == 1:
            axes = [axes] if cols == 1 else axes
        else:
            axes = axes.flatten()

        for idx, (header_key, header_stats) in enumerate(headers_with_validation):
            if idx >= len(axes):
                break
            ax = axes[idx]
            correct_pct = (header_stats['correct'] / header_stats['present']) * 100
            incorrect_pct = 100 - correct_pct
            ax.bar(['Correct', 'Incorrect'], [correct_pct, incorrect_pct],
                color=[self.colors['good'], self.colors['bad']])
            ax.set_title(f"{header_stats.get('display_name', header_key)} Correctness")
            ax.set_ylabel('Percentage (%)')
            self._add_percentages(ax, [correct_pct, incorrect_pct])
            ax.set_ylim(0, 105)

        for idx in range(len(headers_with_validation), len(axes)):
            axes[idx].set_visible(False)

        plt.suptitle('Security Header Correctness (when present)', fontsize=16)
        self._save_plot('header_correctness.png')

    
    def _plot_custom_headers(self, stats: Dict):
        custom_missing = stats.get('custom_missing', {})
        custom_regex = stats.get('custom_regex', {})
        total = stats.get('total', 0)
        
        if not custom_missing and not custom_regex:
            return
        
        plots_needed = 0
        if custom_missing:
            plots_needed += 1
        if custom_regex:
            plots_needed += 1
        
        fig, axes = plt.subplots(1, plots_needed, figsize=(8 * plots_needed, 6))
        if plots_needed == 1:
            axes = [axes]
        
        plot_idx = 0
        
        if custom_missing and total > 0:
            ax = axes[plot_idx]
            headers = list(custom_missing.keys())
            present_counts = [custom_missing[h]['present'] for h in headers]
            present_pcts = [(c / total) * 100 for c in present_counts]
            
            bars = ax.bar(headers, present_pcts, color=self.colors['info'])
            self._add_percentages(ax, present_pcts)
            
            ax.set_title('Custom Required Headers')
            ax.set_ylabel('Presence (%)')
            ax.set_ylim(0, 105)
            ax.tick_params(axis='x', rotation=45)
            
            ax.axhline(y=100, color='green', linestyle='--', alpha=0.5, label='Target')
            
            plot_idx += 1
        
        if custom_regex and total > 0:
            ax = axes[plot_idx]
            headers = list(custom_regex.keys())
            match_counts = [custom_regex[h]['matches'] for h in headers]
            match_pcts = [(c / total) * 100 for c in match_counts]
            
            bars = ax.bar(headers, match_pcts, color=self.colors['info'])
            self._add_percentages(ax, match_pcts)
            
            ax.set_title('Custom Header Pattern Matches')
            ax.set_ylabel('Match Rate (%)')
            ax.set_ylim(0, 105)
            ax.tick_params(axis='x', rotation=45)
            
            ax.axhline(y=100, color='green', linestyle='--', alpha=0.5, label='Target')
        
        plt.suptitle(f'Custom Header Analysis (n={total})', fontsize=16)
        self._save_plot('custom_headers.png')
    
    def plot_tls_support(self, stats: Dict):
        if not stats or stats.get('total', 0) == 0:
            return
        
        total = stats['total']
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        versions = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0']
        supported = [
            (stats['tls1_3']['supported'] / total) * 100,
            (stats['tls1_2']['supported'] / total) * 100,
            (stats['tls1_1']['supported'] / total) * 100,
            (stats['tls1_0']['supported'] / total) * 100
        ]
        
        colors = [self.colors['good'], self.colors['good'], 
                 self.colors['bad'], self.colors['bad']]
        
        bars = ax.bar(versions, supported, color=colors)
        self._add_percentages(ax, supported)
        
        ax.set_ylabel('Support Percentage (%)')
        ax.set_title(f'TLS Version Support (n={total})')
        ax.set_ylim(0, 105)
        
        ax.axhline(y=50, color='gray', linestyle='--', alpha=0.5)
        ax.text(0.02, 0.98, 'Green = Secure versions\nRed = Deprecated versions',
                transform=ax.transAxes, va='top', fontsize=10,
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        self._save_plot('tls_support.png')
    
    def plot_cipher_security(self, stats: Dict):
        if not stats or stats.get('total', 0) == 0:
            return
        
        total = stats['total']
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        levels = ['Recommended', 'Secure', 'Weak', 'Insecure', 'Error']
        values = [
            (stats['cipher_security']['recommended'] / total) * 100,
            (stats['cipher_security']['secure'] / total) * 100,
            (stats['cipher_security']['weak'] / total) * 100,
            (stats['cipher_security']['insecure'] / total) * 100,
            (stats['cipher_security']['error'] / total) * 100
        ]
        colors = [self.colors['good'], self.colors['good'], 
                 self.colors['warning'], self.colors['bad'], self.colors['neutral']]
        
        bars = ax1.bar(levels, values, color=colors)
        self._add_percentages(ax1, values)
        ax1.set_ylabel('Percentage (%)')
        ax1.set_title('Cipher Suite Security Levels')
        ax1.set_ylim(0, 105)
        ax1.tick_params(axis='x', rotation=45)
        
        labels = ['SHA-1 Support', 'CBC Support']
        sha1_yes = (stats['sha1_support']['yes'] / total) * 100
        cbc_yes = (stats['cbc_support']['yes'] / total) * 100
        values = [sha1_yes, cbc_yes]
        
        bars = ax2.bar(labels, values, color=self.colors['bad'])
        self._add_percentages(ax2, values)
        ax2.set_ylabel('Percentage (%)')
        ax2.set_title('Weak Cipher Algorithm Support')
        ax2.set_ylim(0, 105)
        
        plt.suptitle(f'Cipher Suite Analysis (n={total})', fontsize=16)
        self._save_plot('cipher_security.png')
    
    def plot_securitytxt(self, stats: Dict):
        if not stats or stats.get('total', 0) == 0:
            return
        
        total = stats['total']
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
        
        present = (stats['present'] / total) * 100
        absent = (stats['absent'] / total) * 100
        
        ax1.bar(['Implemented', 'Not Implemented'], [present, absent],
                color=[self.colors['good'], self.colors['bad']])
        self._add_percentages(ax1, [present, absent])
        ax1.set_ylabel('Percentage (%)')
        ax1.set_title('security.txt Implementation')
        ax1.set_ylim(0, 105)
        
        if stats['present'] > 0:
            both = (stats['correctness']['both'] / stats['present']) * 100
            contact = (stats['correctness']['contact_only'] / stats['present']) * 100
            expires = (stats['correctness']['expires_only'] / stats['present']) * 100
            none = (stats['correctness']['none'] / stats['present']) * 100
            
            labels = ['Both Fields', 'Contact Only', 'Expires Only', 'Neither']
            values = [both, contact, expires, none]
            colors = [self.colors['good'], self.colors['warning'], 
                     self.colors['warning'], self.colors['bad']]
            
            ax2.bar(labels, values, color=colors)
            self._add_percentages(ax2, values)
            ax2.set_ylabel('Percentage (%)')
            ax2.set_title('security.txt Correctness (when present)')
            ax2.set_ylim(0, 105)
            ax2.tick_params(axis='x', rotation=45)
        
        plt.suptitle(f'security.txt Analysis (n={total})', fontsize=16)
        self._save_plot('securitytxt.png')
    
    def plot_redirection(self, stats: Dict):
        if not stats or stats.get('total', 0) == 0:
            return
        
        total = stats['total']
        
        fig, ax = plt.subplots(figsize=(8, 6))
        
        redirects = (stats['redirects'] / total) * 100
        no_redirect = (stats['no_redirect'] / total) * 100
        errors = (stats['errors'] / total) * 100
        
        labels = ['Redirects to HTTPS', 'No Redirect', 'Connection Error']
        values = [redirects, no_redirect, errors]
        colors = [self.colors['good'], self.colors['bad'], self.colors['neutral']]
        
        bars = ax.bar(labels, values, color=colors)
        self._add_percentages(ax, values)
        
        ax.set_ylabel('Percentage (%)')
        ax.set_title(f'HTTP to HTTPS Redirection (n={total})')
        ax.set_ylim(0, 105)
        
        self._save_plot('http_redirection.png')