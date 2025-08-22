#!/usr/bin/env python3
"""
SubFinder - Advanced subdomain discovery tool
Author: [NoneR00tk1t]
Version: 2.0
"""

import argparse
import asyncio
import aiohttp
import colorama
from colorama import Fore, Style
import sys
import os
import json
import time
from typing import Set, Dict, Any
import dns.resolver
import dns.asyncresolver
from datetime import datetime
import logging
import random

colorama.init(autoreset=True)

def print_banner():
    print(f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala]
{Fore.LIGHTBLACK_EX}
                                                                        
                                                                     πππππ∞≈≠∞π                     
                                                                   ∞≠×-≠×≠≠≠-×≠∞∞=≈≈=∞π             
                                                                π√≈∞∞=÷∞∞∞=×≠÷-=÷≈×≠∞∞=≈            
                                                               √≠÷≈≠≠≠×÷∞≈÷-×≈≠=≠≠÷×∞≠≈=π≠π         
                                                            ∞=÷×≈∞≠≈∞√        π∞≠∞∞==≈≠-×≠-∞        
                                                         ∞≈≠≠≠≠××∞                √××=≠≠=√∞=π       
                                                         ∞≈≈≈≠≠∞≈≠∞                π≈∞=×√∞≈≈∞       
                                                         ∞≠≠≠≠√π∞∞√√ππ              ∞≠==××∞×∞∞      
                                                         π=+++++++-×=≠=≠√           π÷×÷≠≠=÷√×√     
                                                            ∞≈≈∞∞π      π              ∞-=π π∞≠     
                                                                                     ∞≈≠××√=√≠≠     
                                                                                     ≠÷∞∞∞∞∞∞×≠√    
                                                                                     π÷≈∞∞≠≠=×∞÷π   
                                                                                      π≈≠≈÷≠≈÷=≠∞   
                                                                                      √√≈×∞=≠==≠π   
                                                                                       ∞≠≠≈÷÷≠≠∞    
                                                                                      ≈≈∞×-≠≠-÷≠    
                                                                                     ≠-∞≈-≠√≠≠×π    
                                                     ≈∞                           ππ∞∞∞√≈÷√π∞∞π     
                                                  π≠-≠                         √≈÷≈÷=≈≠√≈≠÷÷≠÷π     
                                                 π≠-≠π                     ≈÷÷÷≠≠÷∞≠=×÷=÷×π=≠π      
                                      ∞≠π        π≈=≠∞                   ∞=≠≠∞∞==≠÷+≈≠≠=≠≈ππ        
                                     √÷×√        ∞=÷≠√  √∞∞√           π≠-=×=÷≠∞==≠∞π∞×≈∞∞π         
                                     ∞-=√       π≠≠π   ∞÷≠√        ∞××=≠≈π≠÷≠≠∞√=≠×≠√∞√             
                                      ∞÷=≈     ∞≠=∞    ≠≠π        ≈×÷∞√÷×≈π÷≠≠≈≈×-≠π                
                                      ∞××≈    √=≠π   ∞≠≈√      ≠∞=++×≠∞≠×≠√≠=∞π                     
                                      π≠≠     π∞=≠   ≈≠π    √∞=-≈√≠∞=≠÷××∞π                         
                                      √≠≠≠    ∞≠∞∞   ≠≠π  ∞∞≠-++++-∞√π∞∞π                           
                                      π≈≠π    ∞≠≠≈π π≠≈  π≈×÷≠≠≠≈≠-×××≠√      ππ                    
                                π√    π∞≈≈∞    ≠×≠∞  ≠≠π ≠÷≠≈≈√∞≠≠=×÷∞π       ∞π                    
                                √≠√    π≈≠≠π   π∞≠≠∞π∞==√π≠≠∞≈≠÷-≠π∞√      √∞×≈π     π≠π            
                                 ≈×≈√   √≠≠≠≠∞π  √=÷≠∞√≠××∞≈×+≠==×-×≠√   π∞÷≠π    ππ×-√             
                                   π≈≠    √≠≠∞××≠√≈=≈≈≠≈=×÷≠≈≈≈∞××∞     ≈∞∞π   ∞×=≠+×√              
             π∞≈ π∞≠÷××÷÷≈≈ ∞≠√√π   √≠≈π√   ππ∞≠≈≈∞       π∞÷÷≠∞π    ≈××≠√     =××∞√                
        ∞÷×+÷≠=≠-∞=√∞∞≈÷××÷÷=×≠==∞    π∞≈≠≠÷÷==≠∞≠≈π√≠≈∞∞√π≈≈≠==÷÷÷≠∞∞π    ∞≠≠≠∞                    
      ∞=≠×-××+××≠∞==÷√∞π√√π√≠∞ π√≈÷≠∞        √≠≠≠≠∞≠×=π√√∞∞∞∞∞∞√π      ππ∞√≠≠∞π                     
    ∞≠≈≈+×≠√  π≠==≠≠≠            √≠≠≈∞π      √≠=∞∞≠=≈∞∞∞π≠≠∞√∞≈=÷×=≈∞≈≈∞≠≈≠∞                        
   √+×=-≠        π=+÷              √≠=÷≈     ≠÷≈∞=÷≈≠=≈≠≠≈∞∞∞∞√∞√π∞==≈≠≠∞                           
  π+-≈÷          π=-∞               √≠≠×≠  √÷--÷≠×÷≈=÷≠≈÷≈∞∞≠≠√                     π               
  ≠+≈≠          π÷÷√π                π∞∞∞≠ ≈≠∞≠≠-×∞ ≈÷=÷≠∞π∞≈≠∞π            ≈×≠≠√≠××√               
  ≠+≠         π√√π                    √=÷∞∞=÷∞π∞÷+++÷≠≈√∞≠≈√√≈≠∞≈∞ π√π ∞÷=÷≠×≠≠×+=√                 
  ≈+≈                                 ∞≠≠∞∞÷≠∞=≈π√≈÷÷÷×≠√∞≠∞  ∞=×=≈∞∞=÷×≠∞√πππππ                    
  √-                                  √≠≠∞≈∞π∞∞∞÷×=≠≠≈π  π≠≠√    √√√π√π                             
   ÷                                     π  √≠≠≠=÷=≈π     π∞=∞                                      
   ∞√                                     π∞≈∞∞≠≠≠≈∞≠÷≠∞∞   ∞≠≠≈∞√π                                 
    √                                        √≠÷≠√π√≈≠≠≠≠≈∞π  ππ∞≠≠≠∞πππ                            
                                                        ≈÷≠÷≈ π                                     
                                                          π∞≈≈=∞                                    
                                                           √≠×=√                                    
                                                          π≈≠=≈                                     
                                                           ≠=≠∞                                     
                                                          π≠×÷∞                                     
                                                         π≈≈≠≠√                                     
                                                       ππ≈×≈≠≈                                      
                                                    ∞×++≠≠×≠∞√                                      
                                                  π≠×≈√√≈÷≠≠×-=√                                    
                                                  ≠≠π  π∞∞≠×÷×≠π                                    
                                                 π∞∞      ≠×÷×=√                                    
                                                  ππ      ≈××-≠π                                    
                                                         ∞×÷÷=∞                                     
                                                        ∞×÷∞∞∞                                      
                                                       ≠÷=×=π                                       
                                                     π∞≠+×∞                                         
                                                  ∞÷++-÷∞                                           
                                            π∞∞≈≈≈≈∞√π                                          
{Style.RESET_ALL}
    """)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('subfinder.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('SubFinder')

class SubFinder:
    def __init__(self, domain: str, wordlist: str = None, threads: int = 100, 
                 timeout: int = 10, output: str = None, verbose: bool = False,
                 use_http: bool = False, recursive: bool = False, depth: int = 2):
        self.domain = domain.lower().strip()
        self.wordlist = wordlist or self.get_default_wordlist()
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.verbose = verbose
        self.use_http = use_http
        self.recursive = recursive
        self.depth = depth
        self.found_subdomains: Set[str] = set()
        self.session = None
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.discovered_urls: Dict[str, Any] = {}
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'SubFinder/2.0 Security Scanner'
        ]
        
    def get_default_wordlist(self) -> str:
        default_path = os.path.join(os.path.dirname(__file__), "subdomains.txt")
        if os.path.exists(default_path):
            return default_path
        
        logger.info("Downloading default wordlist...")
        try:
            import requests
            url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
            response = requests.get(url, timeout=30)
            with open(default_path, 'wb') as f:
                f.write(response.content)
            logger.info(f"Wordlist downloaded to {default_path}")
            return default_path
        except Exception as e:
            logger.error(f"Failed to download wordlist: {e}")
            sys.exit(1)
    
    async def init_session(self):
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        self.session = aiohttp.ClientSession(
            connector=connector, 
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'User-Agent': random.choice(self.user_agents)}
        )
    
    async def close_session(self):
        if self.session:
            await self.session.close()
    
    async def check_subdomain(self, subdomain: str) -> bool:
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            answers = await self.resolver.resolve(full_domain, 'A')
            if answers:
                if self.verbose:
                    logger.info(f"Found: {full_domain}")
                self.found_subdomains.add(full_domain)
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            if self.verbose:
                logger.debug(f"DNS error for {full_domain}: {e}")
        
        return False
    
    async def check_http(self, subdomain: str):
        full_domain = f"{subdomain}.{self.domain}"
        protocols = ['https', 'http']  
        
        for protocol in protocols:
            url = f"{protocol}://{full_domain}"
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                async with self.session.get(url, headers=headers, allow_redirects=True, ssl=False) as response:
                    if response.status < 500: 
                        title = await self.get_page_title(response)
                        self.discovered_urls[full_domain] = {
                            'url': url,
                            'status': response.status,
                            'title': title,
                            'headers': dict(response.headers)
                        }
                        return True
            except aiohttp.ClientConnectorError:
                continue
            except asyncio.TimeoutError:
                logger.debug(f"Timeout checking {url}")
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
        return False
    
    async def get_page_title(self, response) -> str:
        try:
            html = await response.text()
            start = html.find('<title>')
            if start == -1:
                start = html.find('<TITLE>')
            end = html.find('</title>')
            if end == -1:
                end = html.find('</TITLE>')
            if start != -1 and end != -1 and end > start:
                return html[start+7:end].strip()[:100]
        except:
            pass
        return ""
    
    async def process_wordlist(self, wordlist_path: str):
        if not os.path.exists(wordlist_path):
            logger.error(f"Wordlist file not found: {wordlist_path}")
            return False
        
        logger.info(f"Processing {os.path.basename(wordlist_path)} with {self.threads} threads...")
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            logger.error(f"Error reading wordlist: {e}")
            return False
        
        semaphore = asyncio.Semaphore(self.threads)
        
        async def limited_check(subdomain):
            async with semaphore:
                return await self.check_subdomain(subdomain)
        
        chunk_size = 1000
        for i in range(0, len(words), chunk_size):
            chunk = words[i:i+chunk_size]
            tasks = [limited_check(word) for word in chunk]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            if i > 0:
                logger.info(f"Processed {min(i+chunk_size, len(words))}/{len(words)} words, "
                           f"found {len(self.found_subdomains)} subdomains so far")
        
        return True
    
    async def recursive_discovery(self, current_domain: str, current_depth: int = 1):
        if current_depth > self.depth:
            return
        
        logger.info(f"Starting recursive discovery at depth {current_depth} for {current_domain}")
        
        sub_finder = SubFinder(
            domain=current_domain,
            wordlist=self.wordlist,
            threads=self.threads // 2,  
            timeout=self.timeout,
            verbose=self.verbose,
            use_http=self.use_http
        )
        
        await sub_finder.init_session()
        try:
            await sub_finder.process_wordlist(self.wordlist)
            self.found_subdomains.update(sub_finder.found_subdomains)
            
            for subdomain in list(sub_finder.found_subdomains):
                if subdomain != current_domain:  
                    await self.recursive_discovery(subdomain, current_depth + 1)
        finally:
            await sub_finder.close_session()
    
    def save_results(self):
        if not self.output:
            return
        
        results = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'subdomains': list(self.found_subdomains),
            'total_found': len(self.found_subdomains),
            'http_services': self.discovered_urls
        }
        
        try:
            if self.output.endswith('.json'):
                with open(self.output, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
            else:
                with open(self.output, 'w', encoding='utf-8') as f:
                    f.write(f"# Subdomain scan results for {self.domain}\n")
                    f.write(f"# Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Total found: {len(self.found_subdomains)}\n\n")
                    
                    f.write("[SUBDOMAINS]\n")
                    for subdomain in sorted(results['subdomains']):
                        f.write(f"{subdomain}\n")
                    
                    if self.discovered_urls:
                        f.write("\n[HTTP SERVICES]\n")
                        for domain, info in self.discovered_urls.items():
                            f.write(f"{domain} -> {info['url']} (Status: {info['status']}, Title: {info['title']})\n")
            
            logger.info(f"Results saved to {self.output}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    async def run(self):
        start_time = time.time()
        
        await self.init_session()
        
        try:
            success = await self.process_wordlist(self.wordlist)
            if not success:
                return
            
            if self.recursive:
                domains_to_process = list(self.found_subdomains)
                for domain in domains_to_process:
                    await self.recursive_discovery(domain)
            
            if self.use_http and self.found_subdomains:
                logger.info(f"Checking HTTP services for {len(self.found_subdomains)} discovered subdomains...")
                
                semaphore = asyncio.Semaphore(self.threads)
                async def limited_http_check(subdomain):
                    async with semaphore:
                        return await self.check_http(subdomain.replace(f".{self.domain}", ""))
                
                http_tasks = [limited_http_check(subdomain) for subdomain in self.found_subdomains]
                await asyncio.gather(*http_tasks, return_exceptions=True)
        
        finally:
            await self.close_session()
        
        elapsed_time = time.time() - start_time
        logger.info(f"\n{'='*60}")
        logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
        logger.info(f"Discovered {len(self.found_subdomains)} subdomains for {self.domain}")
        logger.info(f"{'='*60}")
        
        for subdomain in sorted(self.found_subdomains):
            logger.info(f"FOUND: {subdomain}")
        
        if self.discovered_urls:
            logger.info(f"\nHTTP services found ({len(self.discovered_urls)}):")
            for domain, info in self.discovered_urls.items():
                logger.info(f"  {domain} -> {info['url']} (Status: {info['status']})")
        
        if self.output:
            self.save_results()

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='SubFinder - Advanced subdomain discovery tool')
    parser.add_argument('domain', help='Target domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for each request (default: 10s)')
    parser.add_argument('--http', action='store_true', help='Check HTTP services of found subdomains')
    parser.add_argument('-r', '--recursive', action='store_true', help='Enable recursive subdomain discovery')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Depth for recursive discovery (default: 2)')
    
    args = parser.parse_args()
    
    if args.threads <= 0:
        logger.error("Thread count must be positive")
        sys.exit(1)
    
    if args.depth <= 0:
        logger.error("Depth must be positive")
        sys.exit(1)
    
    finder = SubFinder(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output,
        verbose=args.verbose,
        use_http=args.http,
        recursive=args.recursive,
        depth=args.depth
    )
    
    try:
        asyncio.run(finder.run())
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()