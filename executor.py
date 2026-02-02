"""
Parallel Execution Module

Handles multithreaded NSE script execution using ThreadPoolExecutor.
Manages task queuing, result collection, and thread pool sizing.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime

from scanner import ScanResult, NmapScanner, ScanOptions
from nse_configs import get_service_config_for_port, ScanCategory
from utils import print_status

logger = logging.getLogger("auto_nmap.executor")


@dataclass
class TaskResult:
    """Result of an NSE script execution task."""
    host: str
    port: int
    script: str
    success: bool
    output: str = ""
    error: str = ""
    duration: float = 0.0


@dataclass 
class ExecutorStats:
    """Statistics for executor run."""
    total_tasks: int = 0
    completed: int = 0
    failed: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class NSEExecutor:
    """Executes NSE scripts in parallel using thread pool."""
    
    def __init__(self, max_threads: int = 5):
        """Initialize executor with thread count."""
        self.max_threads = max_threads
        self.stats = ExecutorStats()
        
    def execute_scripts(
        self,
        scan_result: ScanResult,
        include_brute: bool = False,
        include_intrusive: bool = False,
        vuln_only: bool = False,
        safe_only: bool = False,
    ) -> Dict[str, str]:
        """
        Execute NSE scripts based on discovered open ports.
        
        Returns:
            Dictionary mapping "host:port/proto:script" to output
        """
        tasks = []
        
        # Build task list based on open ports
        for host, host_result in scan_result.hosts.items():
            for port, port_info in host_result.open_ports.items():
                # Get scripts for this port
                service_config = get_service_config_for_port(port)
                if not service_config:
                    continue
                
                for script in service_config.scripts:
                    # Filter by category
                    categories = set(script.categories)
                    
                    if vuln_only and ScanCategory.VULN not in categories:
                        continue
                    if safe_only and ScanCategory.SAFE not in categories:
                        continue
                    if not include_brute and ScanCategory.BRUTE in categories:
                        continue
                    if not include_intrusive and ScanCategory.INTRUSIVE in categories:
                        continue
                    
                    tasks.append({
                        "host": host,
                        "port": port,
                        "protocol": port_info.get("protocol", "tcp"),
                        "script": script.name,
                        "args": script.args or "",
                    })
        
        if not tasks:
            print_status("No NSE tasks to execute", "warning")
            return {}
        
        print_status(f"Executing {len(tasks)} NSE script tasks with {self.max_threads} threads", "info")
        
        self.stats = ExecutorStats(
            total_tasks=len(tasks),
            start_time=datetime.now()
        )
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._run_script_task, task): task 
                for task in tasks
            }
            
            for future in as_completed(futures):
                task = futures[future]
                try:
                    result = future.result()
                    if result.success and result.output:
                        key = f"{result.host}:{result.port}/{task['protocol']}:{result.script}"
                        results[key] = result.output
                        self.stats.completed += 1
                    else:
                        self.stats.failed += 1
                except Exception as e:
                    logger.error(f"Task failed: {task} - {e}")
                    self.stats.failed += 1
        
        self.stats.end_time = datetime.now()
        
        duration = (self.stats.end_time - self.stats.start_time).total_seconds()
        print_status(
            f"NSE execution complete: {self.stats.completed}/{self.stats.total_tasks} "
            f"successful in {duration:.1f}s",
            "success"
        )
        
        return results
    
    def _run_script_task(self, task: Dict[str, Any]) -> TaskResult:
        """Execute a single NSE script task."""
        start = datetime.now()
        
        try:
            scanner = NmapScanner(ScanOptions())
            output = scanner.run_nse_script(
                host=task["host"],
                port=task["port"],
                script=task["script"],
                args=task.get("args", ""),
            )
            
            duration = (datetime.now() - start).total_seconds()
            
            if output:
                return TaskResult(
                    host=task["host"],
                    port=task["port"],
                    script=task["script"],
                    success=True,
                    output="\n".join(f"{k}: {v}" for k, v in output.items()),
                    duration=duration,
                )
            else:
                return TaskResult(
                    host=task["host"],
                    port=task["port"],
                    script=task["script"],
                    success=False,
                    error="No output",
                    duration=duration,
                )
                
        except Exception as e:
            return TaskResult(
                host=task["host"],
                port=task["port"],
                script=task["script"],
                success=False,
                error=str(e),
                duration=(datetime.now() - start).total_seconds(),
            )


def run_nse_scans_parallel(
    scan_result: ScanResult,
    threads: int = 5,
    include_brute: bool = False,
    include_intrusive: bool = False,
    vuln_only: bool = False,
    safe_only: bool = False,
) -> Dict[str, str]:
    """
    Convenience function to run NSE scans in parallel.
    
    Args:
        scan_result: Previous scan results with open ports
        threads: Number of parallel threads
        include_brute: Include brute force scripts
        include_intrusive: Include intrusive scripts
        vuln_only: Only run vulnerability scripts
        safe_only: Only run safe scripts
        
    Returns:
        Dictionary mapping script identifiers to output
    """
    executor = NSEExecutor(max_threads=threads)
    return executor.execute_scripts(
        scan_result,
        include_brute=include_brute,
        include_intrusive=include_intrusive,
        vuln_only=vuln_only,
        safe_only=safe_only,
    )
