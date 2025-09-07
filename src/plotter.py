#!/usr/bin/env python3
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Dict, List, Optional

class PlotGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set consistent style
        plt.style.use('default')
        self.colors = {
            'good': 'green',
            'bad': 'red',
            'warning': 'orange',
            'info': 'lightblue',
            'neutral': 'gray'
        }
    
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
   
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        axes = axes.flatten()
        
        ax = axes[0]
        present = (stats['referrer_policy']['present'] / total) * 100
        absent = 100 - present
        ax.bar(['Present', 'Absent'], [present, absent], 
               color=[self.colors['good'], self.colors['bad']])
        ax.set_title('Referrer-Policy Header')
        ax.set_ylabel('Percentage (%)')
        self._add_percentages(ax, [present, absent])
        
        ax = axes[1]
        present = (stats['x_content_type_options']['present'] / total) * 100
        absent = 100 - present
        ax.bar(['Present', 'Absent'], [present, absent],
               color=[self.colors['good'], self.colors['bad']])
        ax.set_title('X-Content-Type-Options Header')
        ax.set_ylabel('Percentage (%)')
        self._add_percentages(ax, [present, absent])
        
        ax = axes[2]
        present = (stats['x_frame_options']['present'] / total) * 100
        absent = 100 - present
        ax.bar(['Present', 'Absent'], [present, absent],
               color=[self.colors['good'], self.colors['bad']])
        ax.set_title('X-Frame-Options Header')
        ax.set_ylabel('Percentage (%)')
        self._add_percentages(ax, [present, absent])
        
        ax = axes[3]
        present = (stats['csp']['present'] / total) * 100
        absent = 100 - present
        ax.bar(['Present', 'Absent'], [present, absent],
               color=[self.colors['good'], self.colors['bad']])
        ax.set_title('Content-Security-Policy Header')
        ax.set_ylabel('Percentage (%)')
        self._add_percentages(ax, [present, absent])
        
        ax = axes[4]
        present = (stats['hsts']['present'] / total) * 100
        absent = 100 - present
        ax.bar(['Present', 'Absent'], [present, absent],
               color=[self.colors['good'], self.colors['bad']])
        ax.set_title('Strict-Transport-Security Header')
        ax.set_ylabel('Percentage (%)')
        self._add_percentages(ax, [present, absent])
        
        ax = axes[5]
        revealing = (stats['revealing_headers']['count'] / total) * 100
        not_revealing = 100 - revealing
        ax.bar(['Has Revealing', 'No Revealing'], [revealing, not_revealing],
               color=[self.colors['bad'], self.colors['good']])
        ax.set_title('Information Revealing Headers')
        ax.set_ylabel('Percentage (%)')
        self._add_percentages(ax, [revealing, not_revealing])
        
        plt.suptitle(f'Security Headers Implementation (n={total})', fontsize=16)
        self._save_plot('security_headers.png')
        
        self._plot_header_correctness(stats)
    
    def _plot_header_correctness(self, stats: Dict):
        """Plot correctness of implemented headers"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        axes = axes.flatten()
        
        ax = axes[0]
        if stats['referrer_policy']['present'] > 0:
            correct = (stats['referrer_policy']['correct'] / stats['referrer_policy']['present']) * 100
            incorrect = 100 - correct
            ax.bar(['Correct', 'Incorrect'], [correct, incorrect],
                   color=[self.colors['good'], self.colors['bad']])
            ax.set_title('Referrer-Policy Correctness (when present)')
            self._add_percentages(ax, [correct, incorrect])
        
        ax = axes[1]
        if stats['x_content_type_options']['present'] > 0:
            correct = (stats['x_content_type_options']['correct'] / stats['x_content_type_options']['present']) * 100
            incorrect = 100 - correct
            ax.bar(['Correct', 'Incorrect'], [correct, incorrect],
                   color=[self.colors['good'], self.colors['bad']])
            ax.set_title('X-Content-Type-Options Correctness (when present)')
            self._add_percentages(ax, [correct, incorrect])
        
        ax = axes[2]
        if stats['x_frame_options']['present'] > 0:
            correct = (stats['x_frame_options']['correct'] / stats['x_frame_options']['present']) * 100
            incorrect = 100 - correct
            ax.bar(['Correct', 'Incorrect'], [correct, incorrect],
                   color=[self.colors['good'], self.colors['bad']])
            ax.set_title('X-Frame-Options Correctness (when present)')
            self._add_percentages(ax, [correct, incorrect])
        
        ax = axes[3]
        if stats['csp']['present'] > 0:
            reasonable = (stats['csp']['reasonable'] / stats['csp']['present']) * 100
            unreasonable = 100 - reasonable
            ax.bar(['Reasonable', 'Unreasonable'], [reasonable, unreasonable],
                   color=[self.colors['good'], self.colors['bad']])
            ax.set_title('CSP Configuration (when present)')
            self._add_percentages(ax, [reasonable, unreasonable])
        
        for ax in axes:
            ax.set_ylabel('Percentage (%)')
            ax.set_ylim(0, 105)
        
        plt.suptitle('Security Header Correctness Analysis', fontsize=16)
        self._save_plot('header_correctness.png')
    
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