#!/usr/bin/env python3
import time
import json
import pandas as pd
import argparse
import numpy as np
from collections import Counter
import matplotlib.pyplot as plt
from tqdm import tqdm
import os
from urllib3.exceptions import InsecureRequestWarning

# Suppress insecure HTTPS warnings for all libraries
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

class TLSFingerprintCollector:
    def __init__(self, server_ip, port=999, iterations=100, output_file="tls_fingerprint_data.json"):
        self.base_url = f"https://{server_ip}:{port}"
        self.endpoints = {
            "ja3": "/ja3",
            "ja4": "/ja4",
            "ja3s": "/ja3s",
            "ja4s": "/ja4s",
            "jarm": "/jarm",
            "jarm_s": "/jarm_s",
            "sslanalyze": "/sslanalyze",
            "sslanalyze_s": "/sslanalyze_s"
        }
        self.iterations = iterations
        self.output_file = output_file
        self.results = {}
        
        # Import HTTP libraries dynamically to handle missing dependencies gracefully
        self.http_libs = {}
        self.import_http_libraries()
        
    def import_http_libraries(self):
        """Import different HTTP request libraries and store them for later use."""
        # Dictionary to store library objects and their names
        http_libs = {}
        
        # Try to import requests
        try:
            import requests
            http_libs["requests"] = {
                "lib": requests,
                "func": self.make_requests_call
            }
            print("✓ Successfully imported 'requests' library")
        except ImportError:
            print("✗ Failed to import 'requests' library")
        
        # Try to import httpx
        try:
            import httpx
            http_libs["httpx"] = {
                "lib": httpx,
                "func": self.make_httpx_call
            }
            print("✓ Successfully imported 'httpx' library")
        except ImportError:
            print("✗ Failed to import 'httpx' library")
        
        # Try to import urllib
        try:
            import urllib.request
            http_libs["urllib"] = {
                "lib": urllib.request,
                "func": self.make_urllib_call
            }
            print("✓ Successfully imported 'urllib' library")
        except ImportError:
            print("✗ Failed to import 'urllib' library")
            
        # Try to import aiohttp (but we'll use it synchronously)
        try:
            import aiohttp
            import asyncio
            http_libs["aiohttp"] = {
                "lib": aiohttp,
                "func": self.make_aiohttp_call,
                "asyncio": asyncio
            }
            print("✓ Successfully imported 'aiohttp' library")
        except ImportError:
            print("✗ Failed to import 'aiohttp' library")
            
        # Try to import http.client (stdlib)
        try:
            import http.client
            import ssl
            http_libs["http.client"] = {
                "lib": http.client,
                "func": self.make_httpclient_call,
                "ssl": ssl
            }
            print("✓ Successfully imported 'http.client' library")
        except ImportError:
            print("✗ Failed to import 'http.client' library")

        self.http_libs = http_libs
        
        if not self.http_libs:
            raise ImportError("No HTTP libraries available. Please install at least one of: requests, httpx, urllib, aiohttp")
    
    def make_requests_call(self, url):
        """Make HTTP request using the requests library."""
        requests = self.http_libs["requests"]["lib"]
        start_time = time.time()
        response = requests.get(url, verify=False, timeout=30)
        end_time = time.time()
        return response.text, response.status_code, end_time - start_time
    
    def make_httpx_call(self, url):
        """Make HTTP request using the httpx library."""
        httpx = self.http_libs["httpx"]["lib"]
        start_time = time.time()
        with httpx.Client(verify=False, timeout=30) as client:
            response = client.get(url)
        end_time = time.time()
        return response.text, response.status_code, end_time - start_time
    
    def make_urllib_call(self, url):
        """Make HTTP request using the urllib library."""
        urllib_req = self.http_libs["urllib"]["lib"]
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        start_time = time.time()
        req = urllib_req.Request(url)
        with urllib_req.urlopen(req, context=ctx, timeout=30) as response:
            content = response.read().decode('utf-8')
            status_code = response.getcode()
        end_time = time.time()
        
        return content, status_code, end_time - start_time
    
    def make_aiohttp_call(self, url):
        """Make HTTP request using the aiohttp library."""
        aiohttp = self.http_libs["aiohttp"]["lib"]
        asyncio = self.http_libs["aiohttp"]["asyncio"]
        
        async def fetch():
            async with aiohttp.ClientSession() as session:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                async with session.get(url, ssl=ssl_context, timeout=30) as response:
                    text = await response.text()
                    return text, response.status
        
        start_time = time.time()
        response = asyncio.run(fetch())
        end_time = time.time()
        
        return response[0], response[1], end_time - start_time
    
    def make_httpclient_call(self, url):
        """Make HTTP request using the http.client library."""
        http_client = self.http_libs["http.client"]["lib"]
        ssl_lib = self.http_libs["http.client"]["ssl"]
        
        # Parse URL to get host, port, and path
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        host = parsed_url.netloc.split(':')[0]
        port = parsed_url.port or 443
        path = parsed_url.path or '/'
        
        # Set up SSL context
        context = ssl_lib.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl_lib.CERT_NONE
        
        start_time = time.time()
        conn = http_client.HTTPSConnection(host, port, context=context, timeout=30)
        conn.request("GET", path)
        response = conn.getresponse()
        content = response.read().decode('utf-8')
        status = response.status
        conn.close()
        end_time = time.time()
        
        return content, status, end_time - start_time
        
    def parse_fingerprint_from_response(self, response_text, endpoint):
        """Extract just the fingerprint part from responses, especially for _s endpoints."""
        if not response_text:
            return None
            
        # For endpoints with timing info (_s endpoints)
        if "_s" in endpoint:
            try:
                # Try to parse as JSON
                data = json.loads(response_text)
                # Different endpoints might structure their JSON differently
                if "fingerprint" in data:
                    return data["fingerprint"]
                elif "hash" in data:
                    return data["hash"]
                # If we can't find a specific fingerprint field, return the whole data except time
                data_copy = data.copy()
                if "time" in data_copy:
                    del data_copy["time"]
                return json.dumps(data_copy)
            except json.JSONDecodeError:
                # If not valid JSON, try to extract fingerprint before timing info
                if "," in response_text:
                    return response_text.split(",")[0].strip()
                return response_text
        
        # For regular endpoints, return the full response
        return response_text
        
    def collect_data(self):
        """Collect fingerprint data for all endpoints using multiple HTTP libraries."""
        print(f"Starting data collection with {self.iterations} iterations per technique...")
        
        for lib_name, lib_info in self.http_libs.items():
            print(f"\n=== Using {lib_name} library ===")
            
            for name, endpoint in tqdm(self.endpoints.items(), desc=f"Fingerprinting with {lib_name}"):
                result_key = f"{lib_name}_{name}"
                self.results[result_key] = {
                    "library": lib_name,
                    "technique": name,
                    "fingerprints": [],
                    "raw_responses": [],
                    "times": [],
                    "errors": 0
                }
                
                for i in tqdm(range(self.iterations), desc=f"Iterations for {name}", leave=False):
                    try:
                        # Use the appropriate function for this library
                        url = f"{self.base_url}{endpoint}"
                        response_text, status_code, client_time = lib_info["func"](url)
                        
                        if status_code == 200:
                            # Store the raw response
                            self.results[result_key]["raw_responses"].append(response_text)
                            
                            # Extract and store just the fingerprint part
                            fingerprint = self.parse_fingerprint_from_response(response_text, endpoint)
                            self.results[result_key]["fingerprints"].append(fingerprint)
                            
                            # For endpoints with timing info, try to extract server-side timing
                            if "_s" in endpoint:
                                try:
                                    data = json.loads(response_text)
                                    if "time" in data:
                                        server_time = float(data["time"])
                                        self.results[result_key]["times"].append(server_time)
                                    else:
                                        self.results[result_key]["times"].append(client_time)
                                except (json.JSONDecodeError, ValueError):
                                    self.results[result_key]["times"].append(client_time)
                            else:
                                # For regular endpoints, use client-side timing
                                self.results[result_key]["times"].append(client_time)
                        else:
                            print(f"Error: Received status code {status_code} for {name} with {lib_name}")
                            self.results[result_key]["errors"] += 1
                    except Exception as e:
                        print(f"Exception occurred for {name} with {lib_name}: {str(e)}")
                        self.results[result_key]["errors"] += 1
                    
                    # Add a small delay between requests to prevent overwhelming the server
                    time.sleep(0.1)
            
    def analyze_data(self):
        """Analyze the collected data for consistency, timing, and uniqueness."""
        analysis = {}
        
        # First, analyze each technique/library combination
        for result_key, data in self.results.items():
            fingerprints = data["fingerprints"]
            times = data["times"]
            
            if not fingerprints:
                print(f"No data collected for {result_key}. Skipping analysis.")
                continue
                
            # Calculate uniqueness/entropy
            unique_count = len(set(fingerprints))
            fingerprint_counter = Counter(fingerprints)
            most_common = fingerprint_counter.most_common(5)
            
            # Calculate consistency (% of most common fingerprint)
            consistency = (most_common[0][1] / len(fingerprints)) * 100 if fingerprints else 0
            
            # Calculate Shannon entropy
            total_count = len(fingerprints)
            probabilities = [count / total_count for count in fingerprint_counter.values()]
            entropy = -sum(p * np.log2(p) for p in probabilities)
            
            # Calculate time statistics
            avg_time = np.mean(times) if times else 0
            min_time = np.min(times) if times else 0
            max_time = np.max(times) if times else 0
            std_time = np.std(times) if times else 0
            
            analysis[result_key] = {
                "library": data["library"],
                "technique": data["technique"],
                "consistency": consistency,
                "unique_fingerprints": unique_count,
                "total_fingerprints": len(fingerprints),
                "uniqueness_ratio": unique_count / len(fingerprints) if fingerprints else 0,
                "entropy": entropy,
                "avg_time": avg_time,
                "min_time": min_time,
                "max_time": max_time,
                "std_time": std_time,
                "errors": data["errors"],
                "most_common": most_common
            }
        
        # Now, analyze cross-library consistency for each technique
        technique_analysis = {}
        
        for endpoint in self.endpoints:
            technique_analysis[endpoint] = {
                "cross_library_data": []
            }
            
            # Collect all fingerprints from all libraries for this technique
            all_fingerprints = []
            lib_fingerprints = {}
            
            for lib_name in self.http_libs:
                result_key = f"{lib_name}_{endpoint}"
                if result_key in self.results and self.results[result_key]["fingerprints"]:
                    fingerprints = self.results[result_key]["fingerprints"]
                    all_fingerprints.extend(fingerprints)
                    
                    # Store most common fingerprint for each library
                    counter = Counter(fingerprints)
                    most_common = counter.most_common(1)[0][0] if counter else None
                    lib_fingerprints[lib_name] = most_common
            
            # Calculate cross-library consistency
            all_counter = Counter(all_fingerprints)
            total_fingerprints = len(all_fingerprints)
            most_common_all = all_counter.most_common(1)[0][0] if all_counter else None
            
            # Count how many libraries have the same most common fingerprint
            matching_libs = sum(1 for fp in lib_fingerprints.values() if fp == most_common_all)
            lib_consistency = (matching_libs / len(lib_fingerprints)) * 100 if lib_fingerprints else 0
            
            # Check if all libraries generate the same fingerprint consistently
            all_match = len(set(fp for fp in lib_fingerprints.values() if fp)) == 1
            
            technique_analysis[endpoint].update({
                "cross_library_consistency": lib_consistency,
                "all_libraries_match": all_match,
                "unique_cross_library_fingerprints": len(all_counter),
                "most_common_fingerprint": most_common_all,
                "library_specific_fingerprints": lib_fingerprints
            })
            
        return analysis, technique_analysis
    
    def save_results(self, analysis, technique_analysis):
        """Save raw results and analysis to file."""
        output = {
            "raw_data": self.results,
            "analysis": analysis,
            "technique_analysis": technique_analysis
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"Results saved to {self.output_file}")
    
    def generate_report(self, analysis, technique_analysis):
        """Generate a summary report of the analysis."""
        print("\n======= TLS FINGERPRINTING ANALYSIS REPORT =======\n")
        
        # Convert to DataFrame for easier comparison
        df = pd.DataFrame({
            'Library': [],
            'Technique': [],
            'Consistency (%)': [],
            'Unique Count': [],
            'Uniqueness Ratio': [],
            'Entropy': [],
            'Avg Time (s)': [],
            'Min Time (s)': [],
            'Max Time (s)': [],
            'Time Std Dev': [],
            'Error Count': []
        })
        
        for result_key, metrics in analysis.items():
            new_row = pd.DataFrame({
                'Library': [metrics['library']],
                'Technique': [metrics['technique']],
                'Consistency (%)': [round(metrics['consistency'], 2)],
                'Unique Count': [metrics['unique_fingerprints']],
                'Uniqueness Ratio': [round(metrics['uniqueness_ratio'], 4)],
                'Entropy': [round(metrics['entropy'], 4)],
                'Avg Time (s)': [round(metrics['avg_time'], 6)],
                'Min Time (s)': [round(metrics['min_time'], 6)],
                'Max Time (s)': [round(metrics['max_time'], 6)],
                'Time Std Dev': [round(metrics['std_time'], 6)],
                'Error Count': [metrics['errors']]
            })
            df = pd.concat([df, new_row], ignore_index=True)
        
        print("Per-Library Analysis:")
        print(df.to_string(index=False))
        
        # Create cross-library analysis DataFrame
        cross_df = pd.DataFrame({
            'Technique': [],
            'Cross-Library Consistency (%)': [],
            'All Libraries Match': [],
            'Unique Cross-Library Fingerprints': []
        })
        
        for endpoint, metrics in technique_analysis.items():
            new_row = pd.DataFrame({
                'Technique': [endpoint],
                'Cross-Library Consistency (%)': [round(metrics['cross_library_consistency'], 2)],
                'All Libraries Match': [metrics['all_libraries_match']],
                'Unique Cross-Library Fingerprints': [metrics['unique_cross_library_fingerprints']]
            })
            cross_df = pd.concat([cross_df, new_row], ignore_index=True)
        
        print("\nCross-Library Analysis:")
        print(cross_df.to_string(index=False))
        
        # Save as CSV for easier analysis
        df.to_csv("tls_fingerprinting_library_summary.csv", index=False)
        cross_df.to_csv("tls_fingerprinting_cross_library_summary.csv", index=False)
        
        print("\nSummary saved to tls_fingerprinting_library_summary.csv")
        print("Cross-library analysis saved to tls_fingerprinting_cross_library_summary.csv")
        
        return df, cross_df
    
    def create_visualizations(self, analysis, technique_analysis, df, cross_df):
        """Create visualizations of the analysis results."""
        # Create visualization directory
        if not os.path.exists("visualizations"):
            os.makedirs("visualizations")
        
        # Group data by technique for comparison across libraries
        for technique in df['Technique'].unique():
            technique_df = df[df['Technique'] == technique]
            
            # Plot consistency by library for this technique
            plt.figure(figsize=(12, 6))
            plt.bar(technique_df['Library'], technique_df['Consistency (%)'])
            plt.title(f'{technique} - Fingerprint Consistency by Library')
            plt.xlabel('Library')
            plt.ylabel('Consistency (%)')
            plt.ylim(0, 105)  # Add some padding above 100%
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f'visualizations/{technique}_consistency_by_library.png')
            
            # Plot average time by library for this technique
            plt.figure(figsize=(12, 6))
            plt.bar(technique_df['Library'], technique_df['Avg Time (s)'])
            plt.title(f'{technique} - Average Processing Time by Library')
            plt.xlabel('Library')
            plt.ylabel('Time (seconds)')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f'visualizations/{technique}_time_by_library.png')
        
        # Plot cross-library consistency
        plt.figure(figsize=(12, 6))
        plt.bar(cross_df['Technique'], cross_df['Cross-Library Consistency (%)'])
        plt.title('Cross-Library Consistency by Technique')
        plt.xlabel('Technique')
        plt.ylabel('Cross-Library Consistency (%)')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('visualizations/cross_library_consistency.png')
        
        # Plot unique cross-library fingerprints
        plt.figure(figsize=(12, 6))
        plt.bar(cross_df['Technique'], cross_df['Unique Cross-Library Fingerprints'])
        plt.title('Unique Cross-Library Fingerprints by Technique')
        plt.xlabel('Technique')
        plt.ylabel('Number of Unique Fingerprints')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('visualizations/cross_library_uniqueness.png')
        
        # Heat map of consistency across techniques and libraries
        pivot_df = df.pivot(index='Library', columns='Technique', values='Consistency (%)')
        plt.figure(figsize=(14, 8))
        plt.imshow(pivot_df, cmap='viridis', interpolation='nearest', aspect='auto')
        plt.colorbar(label='Consistency (%)')
        plt.title('Fingerprinting Consistency Heat Map')
        plt.xticks(range(len(pivot_df.columns)), pivot_df.columns, rotation=45)
        plt.yticks(range(len(pivot_df.index)), pivot_df.index)
        
        # Add text annotations to the heat map
        for i in range(len(pivot_df.index)):
            for j in range(len(pivot_df.columns)):
                value = pivot_df.iloc[i, j]
                if not np.isnan(value):
                    plt.text(j, i, f"{value:.1f}%", ha="center", va="center", 
                             color="white" if value < 50 else "black")
        
        plt.tight_layout()
        plt.savefig('visualizations/consistency_heatmap.png')
        
        print("\nVisualizations saved to the 'visualizations' directory")
    
    def run(self):
        """Run the full data collection and analysis process."""
        self.collect_data()
        analysis, technique_analysis = self.analyze_data()
        self.save_results(analysis, technique_analysis)
        df, cross_df = self.generate_report(analysis, technique_analysis)
        self.create_visualizations(analysis, technique_analysis, df, cross_df)
        print("\nData collection and analysis complete!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced TLS fingerprinting data collection tool")
    parser.add_argument("server_ip", type=str, help="IP address of the TLS fingerprinting server")
    parser.add_argument("--port", type=int, default=999, help="Port of the TLS server (default: 999)")
    parser.add_argument("--iterations", type=int, default=50, help="Number of iterations for each technique (default: 50)")
    parser.add_argument("--output", type=str, default="tls_fingerprint_data.json", help="Output file for raw data (default: tls_fingerprint_data.json)")
    
    args = parser.parse_args()
    
    collector = TLSFingerprintCollector(
        server_ip=args.server_ip,
        port=args.port,
        iterations=args.iterations,
        output_file=args.output
    )
    
    collector.run()