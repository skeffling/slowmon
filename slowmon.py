#!/usr/bin/env python3
"""
MariaDB Slow Query Log Monitor - With Query Fingerprinting
Version: 2.0.0

NEW in v2.0.0:
- Screen 6: Database/Table Breakdown - Track queries by database and table
- Screen 7: Lock Contention Analysis - Identify high lock time queries
- Enhanced query parsing to extract database and table information
- Toggle between database and table view with Tab key
- Drill down into database/table-specific queries

Previous features from v1.9.0:
- Status bar showing system health (Healthy/Warning/Critical)
- Memory usage displayed in footer
- Press Enter on Screen 4 to see full query details
- Enhanced filtering: time range, database, combined filters
- Search functionality: Press '/' to search current view
- Automatic log rotation detection
- Export current view: Press 'e' for CSV/JSON
- Detailed system stats: Press 'd'
- Query age display in Recent view ("5s ago")
"""

import curses
import re
import time
import argparse
import json
import csv
import os
import resource
from collections import deque, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
import sys
import signal
import textwrap
import hashlib

VERSION = "2.0.0"


@dataclass
class SlowQuery:
    __slots__ = ('timestamp', 'query_time', 'lock_time', 'rows_sent', 
                 'rows_examined', 'user', 'host', 'query', 'arrival_time', 'database')
    timestamp: str
    query_time: float
    lock_time: float
    rows_sent: int
    rows_examined: int
    user: str
    host: str
    query: str
    arrival_time: float
    database: str


@dataclass
class QueryPattern:
    """Represents a fingerprinted query pattern"""
    fingerprint: str
    count: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    total_lock_time: float = 0.0
    total_rows_sent: int = 0
    total_rows_examined: int = 0
    last_seen: float = 0.0
    example_query: str = ""
    recent_queries: deque = field(default_factory=lambda: deque(maxlen=10))
    hosts: set = field(default_factory=set)
    users: set = field(default_factory=set)
    
    def add_query(self, query: SlowQuery):
        """Add a query instance to this pattern"""
        self.count += 1
        self.total_time += query.query_time
        self.min_time = min(self.min_time, query.query_time)
        self.max_time = max(self.max_time, query.query_time)
        self.total_lock_time += query.lock_time
        self.total_rows_sent += query.rows_sent
        self.total_rows_examined += query.rows_examined
        self.last_seen = query.arrival_time
        
        if not self.example_query:
            self.example_query = query.query
        
        self.recent_queries.append(query)
        self.hosts.add(query.host)
        self.users.add(query.user)
    
    @property
    def avg_time(self):
        return self.total_time / self.count if self.count > 0 else 0
    
    @property
    def avg_lock_time(self):
        return self.total_lock_time / self.count if self.count > 0 else 0
    
    @property
    def avg_rows_sent(self):
        return self.total_rows_sent / self.count if self.count > 0 else 0
    
    @property
    def avg_rows_examined(self):
        return self.total_rows_examined / self.count if self.count > 0 else 0
    
    @property
    def efficiency(self):
        if self.total_rows_examined > 0:
            return (self.total_rows_sent / self.total_rows_examined) * 100
        return 0
    
    @property
    def impact_score(self):
        """Impact = frequency * avg_time"""
        return self.count * self.avg_time


class QueryFingerprinter:
    """Normalize queries to identify patterns"""
    
    NUMBER_PATTERN = re.compile(r'\b\d+\b')
    STRING_PATTERN = re.compile(r"'[^']*'")
    IN_LIST_PATTERN = re.compile(r'\bIN\s*\([^)]+\)', re.IGNORECASE)
    VALUES_PATTERN = re.compile(r'\bVALUES\s*\([^)]+\)(?:\s*,\s*\([^)]+\))*', re.IGNORECASE)
    LIMIT_PATTERN = re.compile(r'\bLIMIT\s+\d+(?:\s*,\s*\d+)?', re.IGNORECASE)
    
    # Table extraction patterns
    TABLE_PATTERN = re.compile(
        r'(?:FROM|JOIN|INTO|UPDATE)\s+`?([a-zA-Z0-9_]+)`?(?:\s|,|;|\)|$)',
        re.IGNORECASE
    )
    
    @staticmethod
    def fingerprint(query: str) -> str:
        if not query:
            return ""
        
        normalized = ' '.join(query.split())
        normalized = QueryFingerprinter.STRING_PATTERN.sub('?', normalized)
        normalized = QueryFingerprinter.VALUES_PATTERN.sub('VALUES (?+)', normalized)
        normalized = QueryFingerprinter.IN_LIST_PATTERN.sub('IN (?+)', normalized)
        normalized = QueryFingerprinter.LIMIT_PATTERN.sub('LIMIT ?', normalized)
        normalized = QueryFingerprinter.NUMBER_PATTERN.sub('?', normalized)
        
        return normalized
    
    @staticmethod
    def get_pattern_hash(fingerprint: str) -> str:
        return hashlib.md5(fingerprint.encode()).hexdigest()[:8]
    
    @staticmethod
    def extract_tables(query: str) -> list:
        """Extract table names from a query"""
        if not query:
            return []
        
        tables = set()
        matches = QueryFingerprinter.TABLE_PATTERN.findall(query)
        for match in matches:
            # Filter out SQL keywords
            if match.upper() not in ['SELECT', 'WHERE', 'SET', 'VALUES', 'AND', 'OR', 'ON', 'AS']:
                tables.add(match)
        
        return list(tables)


class LatencyBucket:
    __slots__ = ('queries', 'time_windows', '_cache', '_cache_time')
    
    def __init__(self):
        self.queries = deque()
        self.time_windows = {10: 0, 60: 0, 600: 0, 3600: 0, 21600: 0}
        self._cache = None
        self._cache_time = 0
    
    def add(self, arrival_time, query_time, host, query):
        self.queries.append((arrival_time, query_time, host, query))
        self._cache = None
    
    def get_counts(self, current_time):
        if self._cache is not None and current_time - self._cache_time < 1.0:
            return self._cache
        
        cutoff = current_time - 21600
        while self.queries and self.queries[0][0] < cutoff:
            self.queries.popleft()
        
        counts = {10: 0, 60: 0, 600: 0, 3600: 0, 21600: 0}
        for arrival_time, _, _, _ in self.queries:
            age = current_time - arrival_time
            if age <= 10: counts[10] += 1
            if age <= 60: counts[60] += 1
            if age <= 600: counts[600] += 1
            if age <= 3600: counts[3600] += 1
            if age <= 21600: counts[21600] += 1
        
        self._cache = counts
        self._cache_time = current_time
        return counts


class SlowLogMonitor:
    USER_PATTERN = re.compile(r'# User@Host: (\S+)\[(\S+)\] @ (\S*) \[([^\]]*)\]')
    STATS_PATTERN = re.compile(
        r'# Query_time:\s+([\d.]+)\s+Lock_time:\s+([\d.]+)\s+Rows_sent:\s+(\d+)\s+Rows_examined:\s+(\d+)'
    )
    
    def __init__(self, log_path, refresh_rate=10.0, max_queries=10000, debug=False, from_start=False, low_cpu=False):
        self.log_path = Path(log_path)
        self.refresh_rate = refresh_rate
        self.max_queries = max_queries
        self.debug = debug
        self.from_start = from_start
        self.low_cpu = low_cpu
        
        if self.debug:
            self.debug_file = open('/tmp/mariadb_monitor_debug.txt', 'w')
            self.debug_file.write("Debug mode started\n")
            self.debug_file.flush()
        else:
            self.debug_file = None
        
        self.latency_buckets = {
            10: LatencyBucket(), 100: LatencyBucket(), 500: LatencyBucket(),
            1000: LatencyBucket(), float('inf'): LatencyBucket()
        }
        
        self.host_latency = defaultdict(lambda: {
            10: LatencyBucket(), 100: LatencyBucket(), 500: LatencyBucket(),
            1000: LatencyBucket(), float('inf'): LatencyBucket()
        })
        
        self.host_user_latency = defaultdict(lambda: {
            10: LatencyBucket(), 100: LatencyBucket(), 500: LatencyBucket(),
            1000: LatencyBucket(), float('inf'): LatencyBucket()
        })
        
        self.query_type_latency = defaultdict(lambda: {
            10: LatencyBucket(), 100: LatencyBucket(), 500: LatencyBucket(),
            1000: LatencyBucket(), float('inf'): LatencyBucket()
        })
        
        self.recent_critical = deque(maxlen=50000)
        
        self.query_patterns = {}
        self.pattern_sort_mode = 0
        self.fingerprinter = QueryFingerprinter()
        
        # Database and table tracking
        self.database_stats = defaultdict(lambda: {
            'count': 0, 'total_time': 0, 'total_lock_time': 0,
            'total_rows_sent': 0, 'total_rows_examined': 0, 'queries': deque(maxlen=10)
        })
        self.table_stats = defaultdict(lambda: {
            'count': 0, 'total_time': 0, 'total_lock_time': 0,
            'total_rows_sent': 0, 'total_rows_examined': 0, 'database': '', 'queries': deque(maxlen=10)
        })
        self.db_sort_mode = 0
        self.table_sort_mode = 0
        
        # Lock contention tracking
        self.high_lock_queries = deque(maxlen=1000)  # Queries with lock_time > 0.1s
        self.lock_sort_mode = 0
        
        self.pattern_filter_host = ""
        self.pattern_filter_active = False
        
        # Log rotation detection
        self.log_inode = None
        if self.log_path.exists():
            self.log_inode = os.stat(self.log_path).st_ino
        
        if not from_start and self.log_path.exists():
            self.file_position = self.log_path.stat().st_size
            self.file_size = self.file_position
        else:
            self.file_position = 0
            self.file_size = 0
        
        self.paused = False
        self.view_mode = 0
        self.scroll_offset = 0
        self.selected_index = 0
        self.host_sort_mode = 0
        self.qtype_sort_mode = 0
        self.total_queries = 0
        self.parse_errors = 0
        
        # Search functionality
        self.search_mode = False
        self.search_query = ""
        self.search_results = []
        
        # Enhanced filtering
        self.time_filter = None  # None, '5m', '1h', '1d'
        self.filter_text = ""
        
        self.pattern_filters = {
            'host': '',
            'user': '',
            'min_count': 0,
            'min_avg_time': 0.0,
            'max_efficiency': 100.0,
        }
        self.filters_active = False
        self.last_parse_time = 0
        self.buffer = ""
        self.start_time = None
        self.last_update_time = None
        
        self.qps_history = deque(maxlen=60)
        self.slow_query_history = deque(maxlen=60)
        self.host_qps_history = defaultdict(lambda: deque(maxlen=30))
        self.host_slow_history = defaultdict(lambda: deque(maxlen=30))
        self.qtype_qps_history = defaultdict(lambda: deque(maxlen=30))
        self.qtype_slow_history = defaultdict(lambda: deque(maxlen=30))
        
        self._sparkline_cache = {}
        self._sparkline_cache_time = {}
        self._format_cache = {}
        self._format_cache_time = 0
        
        self.should_exit = False
        self.data_changed = True
        
    def _classify_latency(self, query_time_ms):
        if query_time_ms < 10: return 10
        elif query_time_ms < 100: return 100
        elif query_time_ms < 500: return 500
        elif query_time_ms < 1000: return 1000
        else: return float('inf')
    
    def _get_query_type(self, query):
        first_char = query[0].upper() if query else ''
        
        if first_char == 'S':
            if query[:6].upper() == 'SELECT': return 'SELECT'
            elif query[:4].upper() == 'SHOW': return 'SHOW'
            elif query[:3].upper() == 'SET': return 'SET'
        elif first_char == 'I':
            if query[:6].upper() == 'INSERT': return 'INSERT'
        elif first_char == 'U':
            if query[:6].upper() == 'UPDATE': return 'UPDATE'
            elif query[:3].upper() == 'USE': return 'USE'
        elif first_char == 'D':
            if query[:6].upper() == 'DELETE': return 'DELETE'
            elif query[:8].upper() == 'DESCRIBE': return 'DESCRIBE'
            elif query[:4].upper() == 'DESC': return 'DESCRIBE'
            elif query[:4].upper() == 'DROP': return 'DROP'
        elif first_char == 'R':
            if query[:7].upper() == 'REPLACE': return 'REPLACE'
        elif first_char == 'C':
            if query[:6].upper() == 'CREATE': return 'CREATE'
        elif first_char == 'A':
            if query[:5].upper() == 'ALTER': return 'ALTER'
        elif first_char == 'T':
            if query[:8].upper() == 'TRUNCATE': return 'TRUNCATE'
        elif first_char == 'E':
            if query[:7].upper() == 'EXPLAIN': return 'EXPLAIN'
        
        return 'OTHER'
    
    def _should_show_time_window(self, window_seconds):
        """Check if enough time has passed to show this time window"""
        if self.start_time is None:
            return False
        
        elapsed = time.time() - self.start_time
        return elapsed >= (window_seconds * 0.9)
    
    def _get_memory_usage(self):
        """Get current memory usage in MB"""
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            # maxrss is in KB on Linux, bytes on macOS
            if sys.platform == 'darwin':
                return usage.ru_maxrss / 1024 / 1024
            else:
                return usage.ru_maxrss / 1024
        except:
            return 0
    
    def _get_system_health(self):
        """Calculate system health status"""
        current_time = time.time()
        
        # Count recent slow queries (last minute)
        recent_slow = sum(1 for q in self.recent_critical 
                         if current_time - q.arrival_time < 60 and q.query_time * 1000 > 1000)
        
        # Get current QPS
        current_qps = self.qps_history[-1] if self.qps_history else 0
        
        # Count very slow queries (last 10s)
        very_slow = sum(1 for q in self.recent_critical 
                       if current_time - q.arrival_time < 10 and q.query_time * 1000 > 5000)
        
        # Determine status
        if very_slow > 5 or recent_slow > 100:
            return "CRITICAL", 6  # Red
        elif recent_slow > 20 or current_qps > 1000:
            return "WARNING", 4  # Yellow
        else:
            return "HEALTHY", 3  # Green
    
    def _format_time_ago(self, timestamp):
        """Format time difference as '5s ago', '2m ago', etc."""
        diff = time.time() - timestamp
        
        if diff < 60:
            return f"{int(diff)}s ago"
        elif diff < 3600:
            return f"{int(diff/60)}m ago"
        elif diff < 86400:
            return f"{int(diff/3600)}h ago"
        else:
            return f"{int(diff/86400)}d ago"
    
    def _detect_log_rotation(self):
        """Check if log file has been rotated"""
        try:
            if not self.log_path.exists():
                return False
            
            current_inode = os.stat(self.log_path).st_ino
            
            if self.log_inode is not None and current_inode != self.log_inode:
                # Log has been rotated
                self.log_inode = current_inode
                self.file_position = 0
                self.file_size = 0
                return True
            
            self.log_inode = current_inode
            return False
        except:
            return False
    
    def parse_slow_log(self):
        # Check for log rotation
        if self._detect_log_rotation():
            if self.debug_file:
                self.debug_file.write("Log rotation detected, reopening file\n")
                self.debug_file.flush()
        
        if not self.log_path.exists():
            return 0
        
        start_time = time.time()
        new_count = 0
        new_slow_count = 0
        current_time = time.time()
        
        host_counts = defaultdict(int)
        host_slow_counts = defaultdict(int)
        qtype_counts = defaultdict(int)
        qtype_slow_counts = defaultdict(int)
        
        try:
            current_size = self.log_path.stat().st_size
            
            if current_size <= self.file_size:
                return 0
            
            with open(self.log_path, 'rb') as f:
                f.seek(self.file_position)
                chunk_size = min(1024 * 1024, current_size - self.file_position)
                data = f.read(chunk_size)
                
                if not data:
                    return 0
                
                try:
                    text = data.decode('utf-8', errors='ignore')
                except:
                    text = data.decode('latin-1', errors='ignore')
                
                text = self.buffer + text
                entries = text.split('# User@Host:')
                
                self.buffer = '# User@Host:' + entries[-1] if len(entries) > 1 else text
                if text.endswith('\n') and '# User@Host:' in text:
                    self.buffer = ""
                    entries_to_parse = entries[1:]
                else:
                    entries_to_parse = entries[1:-1]
                
                self.file_position = f.tell() - len(self.buffer.encode('utf-8'))
                self.file_size = current_size
                
                for entry in entries_to_parse:
                    query_obj = self._fast_parse_entry(entry, current_time)
                    if query_obj:
                        self._update_latency_buckets(query_obj, current_time)
                        self._add_to_patterns(query_obj)
                        
                        new_count += 1
                        self.total_queries += 1
                        
                        qtype = self._get_query_type(query_obj.query)
                        host_counts[query_obj.host] += 1
                        qtype_counts[qtype] += 1
                        
                        if query_obj.query_time * 1000 > 100:
                            new_slow_count += 1
                            host_slow_counts[query_obj.host] += 1
                            qtype_slow_counts[qtype] += 1
                    else:
                        self.parse_errors += 1
                        
        except Exception as e:
            self.parse_errors += 1
        
        self.last_parse_time = time.time() - start_time
        
        if new_count > 0:
            qps = new_count / self.refresh_rate
            self.qps_history.append(qps)
            self.slow_query_history.append(new_slow_count)
            
            for host, count in host_counts.items():
                host_qps = count / self.refresh_rate
                self.host_qps_history[host].append(host_qps)
                self.host_slow_history[host].append(host_slow_counts.get(host, 0))
            
            for qtype, count in qtype_counts.items():
                qtype_qps = count / self.refresh_rate
                self.qtype_qps_history[qtype].append(qtype_qps)
                self.qtype_slow_history[qtype].append(qtype_slow_counts.get(qtype, 0))
            
            self._sparkline_cache.clear()
            self._format_cache.clear()
            self.data_changed = True
        
        return new_count
    
    def _add_to_patterns(self, query: SlowQuery):
        fingerprint = self.fingerprinter.fingerprint(query.query)
        
        if fingerprint not in self.query_patterns:
            self.query_patterns[fingerprint] = QueryPattern(fingerprint=fingerprint)
        
        self.query_patterns[fingerprint].add_query(query)
    
    def _fast_parse_entry(self, entry, arrival_time):
        try:
            full_entry = '# User@Host: ' + entry
            
            user_match = self.USER_PATTERN.search(full_entry, 0, 300)
            if not user_match:
                simple_match = re.search(r'(\S+)\[(\S+)\] @ (\S*) \[([^\]]*)\]', entry[:300])
                if not simple_match:
                    return None
                user = simple_match.group(2)
                hostname = simple_match.group(3).strip()
                ip_address = simple_match.group(4).strip()
            else:
                user = user_match.group(2)
                hostname = user_match.group(3).strip()
                ip_address = user_match.group(4).strip()
            
            if hostname and hostname not in ['', 'localhost']:
                host = hostname
            elif ip_address:
                host = ip_address
            else:
                host = 'localhost'
            
            stats_match = self.STATS_PATTERN.search(entry, 0, 500)
            if not stats_match:
                return None
            
            query_time = float(stats_match.group(1))
            lock_time = float(stats_match.group(2))
            rows_sent = int(stats_match.group(3))
            rows_examined = int(stats_match.group(4))
            
            # Extract database from Schema line
            database = ""
            schema_match = re.search(r'# Schema:\s+(\S+)', entry)
            if schema_match:
                database = schema_match.group(1)
            
            timestamp_match = re.search(r'SET timestamp=(\d+);', entry)
            if timestamp_match:
                ts = int(timestamp_match.group(1))
                timestamp = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            else:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            ts_pos = entry.find('SET timestamp=')
            if ts_pos != -1:
                query_start = entry.find(';', ts_pos) + 1
                query = entry[query_start:].strip().rstrip(';').strip()
            else:
                lines = entry.split('\n')
                query_lines = []
                for line in lines:
                    line = line.strip()
                    if not line.startswith('#') and not line.startswith('SET timestamp'):
                        if line and not line.startswith('Thread_id') and not line.startswith('Schema'):
                            query_lines.append(line)
                query = ' '.join(query_lines)
            
            query = ' '.join(query.split())
            
            if not query or len(query) < 5:
                return None
            
            return SlowQuery(
                timestamp=timestamp, query_time=query_time, lock_time=lock_time,
                rows_sent=rows_sent, rows_examined=rows_examined, user=user,
                host=host, query=query, arrival_time=arrival_time, database=database if database else ""
            )
        except:
            return None
    
    def _update_latency_buckets(self, query, current_time):
        query_time_ms = query.query_time * 1000
        bucket = self._classify_latency(query_time_ms)
        query_type = self._get_query_type(query.query)
        
        self.latency_buckets[bucket].add(query.arrival_time, query.query_time, query.host, query.query)
        self.host_latency[query.host][bucket].add(query.arrival_time, query.query_time, query.host, query.query)
        
        host_user_key = f"{query.host}@{query.user}"
        self.host_user_latency[host_user_key][bucket].add(query.arrival_time, query.query_time, query.host, query.query)
        
        self.query_type_latency[query_type][bucket].add(query.arrival_time, query.query_time, query.host, query.query)
        
        # Track database stats
        if query.database:
            db_stats = self.database_stats[query.database]
            db_stats['count'] += 1
            db_stats['total_time'] += query.query_time
            db_stats['total_lock_time'] += query.lock_time
            db_stats['total_rows_sent'] += query.rows_sent
            db_stats['total_rows_examined'] += query.rows_examined
            db_stats['queries'].append(query)
        
        # Track table stats
        tables = self.fingerprinter.extract_tables(query.query)
        for table in tables:
            table_key = f"{query.database}.{table}" if query.database else table
            tbl_stats = self.table_stats[table_key]
            tbl_stats['count'] += 1
            tbl_stats['total_time'] += query.query_time
            tbl_stats['total_lock_time'] += query.lock_time
            tbl_stats['total_rows_sent'] += query.rows_sent
            tbl_stats['total_rows_examined'] += query.rows_examined
            tbl_stats['database'] = query.database
            tbl_stats['queries'].append(query)
        
        # Track high lock time queries
        if query.lock_time > 0.1:  # More than 100ms lock time
            self.high_lock_queries.append(query)
        
        if query_time_ms > 100:
            query.arrival_time = current_time
            self.recent_critical.append(query)
    
    def draw_header(self, stdscr, height, width, next_refresh):
        views = ["GLOBAL DIST", "BY HOST", "BY QUERY TYPE", "RECENT CRITICAL", "QUERY PATTERNS", "DB/TABLE", "LOCK CONTENTION"]
        status_icon = "||" if self.paused else ">"
        qps = self.total_queries / max(time.time() - self.start_time, 1)
        unique_hosts = len(self.host_latency)
        unique_host_users = len(self.host_user_latency)
        
        refresh_in = int(max(0, next_refresh))
        
        cpu_mode = " [LOW-CPU]" if self.low_cpu else ""
        
        if self.view_mode == 1:
            host_info = f"H+U: {unique_host_users}"
        else:
            host_info = f"Hosts: {unique_hosts}"
        
        # Build header with colored/bold components
        try:
            stdscr.attron(curses.color_pair(1))
            x = 0
            
            # Base info
            part = f" MariaDB Monitor v{VERSION}{cpu_mode} | {views[self.view_mode]} | {status_icon} | QPS: "
            stdscr.addstr(0, x, part)
            x += len(part)
            
            # QPS value (bold)
            stdscr.attron(curses.A_BOLD)
            part = f"{qps:.1f}"
            stdscr.addstr(0, x, part)
            x += len(part)
            stdscr.attroff(curses.A_BOLD)
            
            # Total label
            part = " | Total: "
            stdscr.addstr(0, x, part)
            x += len(part)
            
            # Total value (bold)
            stdscr.attron(curses.A_BOLD)
            part = f"{self.total_queries}"
            stdscr.addstr(0, x, part)
            x += len(part)
            stdscr.attroff(curses.A_BOLD)
            
            # Hosts label
            part = f" | {host_info.split(':')[0]}: "
            stdscr.addstr(0, x, part)
            x += len(part)
            
            # Hosts value (bold)
            stdscr.attron(curses.A_BOLD)
            part = host_info.split(':')[1].strip()
            stdscr.addstr(0, x, part)
            x += len(part)
            stdscr.attroff(curses.A_BOLD)
            
            # Next refresh label
            part = " | Next: "
            stdscr.addstr(0, x, part)
            x += len(part)
            
            # Next refresh value (bold)
            stdscr.attron(curses.A_BOLD)
            part = f"{refresh_in}s"
            stdscr.addstr(0, x, part)
            x += len(part)
            stdscr.attroff(curses.A_BOLD)
            
            # Pad rest of line
            remaining = " " * (width - x - 1)
            if len(remaining) > 0:
                stdscr.addstr(0, x, remaining)
            
            stdscr.attroff(curses.color_pair(1))
        except:
            pass
    
    def draw_status_bar(self, stdscr, height, width):
        """Draw status bar showing system health - DEPRECATED: Now in footer"""
        pass
    
    def show_query_details_popup(self, stdscr, query):
        """Show detailed popup for a specific query"""
        height, width = stdscr.getmaxyx()
        
        popup_height = min(height - 4, 35)
        popup_width = min(width - 8, 100)
        
        start_y = (height - popup_height) // 2
        start_x = (width - popup_width) // 2
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        popup.keypad(1)
        
        scroll_offset = 0
        
        while True:
            popup.clear()
            popup.box()
            
            title = " Query Details (ESC to close, ↑↓ scroll) "
            try:
                popup.attron(curses.color_pair(1) | curses.A_BOLD)
                popup.addstr(0, (popup_width - len(title)) // 2, title)
                popup.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            query_time_ms = query.query_time * 1000
            lock_time_ms = query.lock_time * 1000
            age = self._format_time_ago(query.arrival_time)
            
            if query.rows_examined > 0:
                efficiency = (query.rows_sent / query.rows_examined) * 100
            else:
                efficiency = 0
            
            fingerprint = self.fingerprinter.fingerprint(query.query)
            
            content = [
                "",
                "═══ Query Information ═══",
                f"Executed: {age}",
                f"Timestamp: {query.timestamp}",
                f"Host: {query.host}",
                f"User: {query.user}",
                f"Type: {self._get_query_type(query.query)}",
                "",
                "═══ Performance Metrics ═══",
                f"Query Time: {query_time_ms:.2f}ms",
                f"Lock Time: {lock_time_ms:.2f}ms",
                f"Rows Sent: {query.rows_sent:,}",
                f"Rows Examined: {query.rows_examined:,}",
                f"Efficiency: {efficiency:.2f}%",
                "",
            ]
            
            # Add efficiency warning
            if query.rows_examined > 1000 and efficiency < 10:
                content.append("⚠ WARNING: Low efficiency - possible missing index")
                content.append("")
            elif efficiency > 80:
                content.append("✓ Good: High efficiency query")
                content.append("")
            
            content.append("═══ Query Fingerprint ═══")
            wrapped_fp = textwrap.wrap(fingerprint, width=popup_width - 6)
            for line in wrapped_fp:
                content.append(line)
            
            content.append("")
            content.append("═══ Full Query ═══")
            wrapped_query = textwrap.wrap(query.query, width=popup_width - 6)
            for line in wrapped_query:
                content.append(line)
            
            y = 2
            max_lines = popup_height - 4
            
            for line in content[scroll_offset:scroll_offset + max_lines]:
                if y >= popup_height - 2:
                    break
                
                try:
                    if "⚠" in line or "WARNING" in line:
                        popup.attron(curses.color_pair(6))
                        popup.addstr(y, 2, line[:popup_width - 4])
                        popup.attroff(curses.color_pair(6))
                    elif "✓" in line:
                        popup.attron(curses.color_pair(3))
                        popup.addstr(y, 2, line[:popup_width - 4])
                        popup.attroff(curses.color_pair(3))
                    elif line.startswith("═"):
                        popup.attron(curses.A_BOLD)
                        popup.addstr(y, 2, line[:popup_width - 4])
                        popup.attroff(curses.A_BOLD)
                    else:
                        popup.addstr(y, 2, line[:popup_width - 4])
                except:
                    pass
                y += 1
            
            if len(content) > max_lines:
                try:
                    scroll_info = f" [{scroll_offset + 1}-{min(scroll_offset + max_lines, len(content))}/{len(content)}] "
                    popup.addstr(popup_height - 1, popup_width - len(scroll_info) - 2, scroll_info)
                except:
                    pass
            
            popup.refresh()
            popup.timeout(100)
            key = popup.getch()
            
            if key == 27 or key == ord('q'):
                break
            elif key == curses.KEY_UP:
                scroll_offset = max(0, scroll_offset - 1)
            elif key == curses.KEY_DOWN:
                scroll_offset = min(len(content) - max_lines, scroll_offset + 1)
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_host_queries_popup(self, stdscr, host_user_key):
        """Show recent queries from a specific host+user"""
        height, width = stdscr.getmaxyx()
        
        popup_height = height - 4
        popup_width = width - 8
        
        start_y = 2
        start_x = 4
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        popup.keypad(1)
        
        # Extract host from host_user_key
        if '@' in host_user_key:
            host_part, user_part = host_user_key.rsplit('@', 1)
        else:
            host_part = host_user_key
            user_part = ""
        
        # Get recent queries from this host
        queries = [q for q in self.recent_critical if q.host == host_part]
        if user_part:
            queries = [q for q in queries if q.user == user_part]
        
        queries.reverse()  # Most recent first
        
        selected_idx = 0
        scroll_offset = 0
        
        while True:
            popup.clear()
            popup.box()
            
            title = f" Queries from {host_user_key} ({len(queries)} total) - [↑↓] navigate [Enter] details [ESC] back "
            try:
                popup.attron(curses.color_pair(1) | curses.A_BOLD)
                popup.addstr(0, 2, title[:popup_width - 4])
                popup.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            if not queries:
                try:
                    popup.addstr(popup_height // 2, 2, "No recent queries from this host+user")
                except:
                    pass
                popup.refresh()
                popup.timeout(-1)
                key = popup.getch()
                if key == 27:
                    break
                continue
            
            # Draw query list
            header = f"{'Time':<10} {'Age':<10} {'QTime':<10} Query"
            try:
                popup.attron(curses.A_BOLD)
                popup.addstr(2, 2, header[:popup_width - 4])
                popup.attroff(curses.A_BOLD)
            except:
                pass
            
            y = 3
            max_lines = popup_height - 5
            
            visible_start = scroll_offset
            visible_end = min(len(queries), visible_start + max_lines)
            
            for idx, query in enumerate(queries[visible_start:visible_end], start=visible_start):
                if y >= popup_height - 2:
                    break
                
                time_str = query.timestamp[-8:] if len(query.timestamp) >= 8 else query.timestamp
                age_str = self._format_time_ago(query.arrival_time)
                query_time_ms = query.query_time * 1000
                query_str = query.query[:max(1, popup_width - 40)]
                
                line = f"{time_str:<10} {age_str:<10} {query_time_ms:<10.1f} {query_str}"
                
                try:
                    if query_time_ms < 100:
                        color = 3
                    elif query_time_ms < 500:
                        color = 4
                    elif query_time_ms < 1000:
                        color = 5
                    else:
                        color = 6
                    
                    if idx == selected_idx:
                        popup.attron(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attron(curses.color_pair(color))
                    
                    popup.addstr(y, 2, line[:popup_width - 4])
                    
                    if idx == selected_idx:
                        popup.attroff(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attroff(curses.color_pair(color))
                except:
                    pass
                y += 1
            
            # Show scroll indicator
            if len(queries) > max_lines:
                try:
                    scroll_info = f" [{scroll_offset + 1}-{min(scroll_offset + max_lines, len(queries))}/{len(queries)}] "
                    popup.addstr(popup_height - 1, popup_width - len(scroll_info) - 2, scroll_info)
                except:
                    pass
            
            popup.refresh()
            popup.timeout(100)
            key = popup.getch()
            
            if key == 27:  # ESC
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                selected_idx = min(len(queries) - 1, selected_idx + 1)
                if selected_idx >= scroll_offset + max_lines:
                    scroll_offset = selected_idx - max_lines + 1
            elif key == 10 or key == curses.KEY_ENTER:
                if 0 <= selected_idx < len(queries):
                    self.show_query_details_popup(stdscr, queries[selected_idx])
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_query_type_queries_popup(self, stdscr, query_type):
        """Show recent queries of a specific type"""
        height, width = stdscr.getmaxyx()
        
        popup_height = height - 4
        popup_width = width - 8
        
        start_y = 2
        start_x = 4
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        popup.keypad(1)
        
        # Get recent queries of this type
        queries = [q for q in self.recent_critical if self._get_query_type(q.query) == query_type]
        queries.reverse()  # Most recent first
        
        selected_idx = 0
        scroll_offset = 0
        
        while True:
            popup.clear()
            popup.box()
            
            title = f" {query_type} Queries ({len(queries)} total) - [↑↓] navigate [Enter] details [ESC] back "
            try:
                popup.attron(curses.color_pair(1) | curses.A_BOLD)
                popup.addstr(0, 2, title[:popup_width - 4])
                popup.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            if not queries:
                try:
                    popup.addstr(popup_height // 2, 2, f"No recent {query_type} queries tracked")
                except:
                    pass
                popup.refresh()
                popup.timeout(-1)
                key = popup.getch()
                if key == 27:
                    break
                continue
            
            # Draw query list
            header = f"{'Time':<10} {'Age':<10} {'Host':<20} {'QTime':<10} Query"
            try:
                popup.attron(curses.A_BOLD)
                popup.addstr(2, 2, header[:popup_width - 4])
                popup.attroff(curses.A_BOLD)
            except:
                pass
            
            y = 3
            max_lines = popup_height - 5
            
            visible_start = scroll_offset
            visible_end = min(len(queries), visible_start + max_lines)
            
            for idx, query in enumerate(queries[visible_start:visible_end], start=visible_start):
                if y >= popup_height - 2:
                    break
                
                time_str = query.timestamp[-8:] if len(query.timestamp) >= 8 else query.timestamp
                age_str = self._format_time_ago(query.arrival_time)
                query_time_ms = query.query_time * 1000
                query_str = query.query[:max(1, popup_width - 60)]
                
                line = f"{time_str:<10} {age_str:<10} {query.host:<20} {query_time_ms:<10.1f} {query_str}"
                
                try:
                    if query_time_ms < 100:
                        color = 3
                    elif query_time_ms < 500:
                        color = 4
                    elif query_time_ms < 1000:
                        color = 5
                    else:
                        color = 6
                    
                    if idx == selected_idx:
                        popup.attron(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attron(curses.color_pair(color))
                    
                    popup.addstr(y, 2, line[:popup_width - 4])
                    
                    if idx == selected_idx:
                        popup.attroff(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attroff(curses.color_pair(color))
                except:
                    pass
                y += 1
            
            # Show scroll indicator
            if len(queries) > max_lines:
                try:
                    scroll_info = f" [{scroll_offset + 1}-{min(scroll_offset + max_lines, len(queries))}/{len(queries)}] "
                    popup.addstr(popup_height - 1, popup_width - len(scroll_info) - 2, scroll_info)
                except:
                    pass
            
            popup.refresh()
            popup.timeout(100)
            key = popup.getch()
            
            if key == 27:  # ESC
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                selected_idx = min(len(queries) - 1, selected_idx + 1)
                if selected_idx >= scroll_offset + max_lines:
                    scroll_offset = selected_idx - max_lines + 1
            elif key == 10 or key == curses.KEY_ENTER:
                if 0 <= selected_idx < len(queries):
                    self.show_query_details_popup(stdscr, queries[selected_idx])
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_pattern_queries_popup(self, stdscr, pattern):
        """Show recent queries matching a specific pattern"""
        height, width = stdscr.getmaxyx()
        
        popup_height = height - 4
        popup_width = width - 8
        
        start_y = 2
        start_x = 4
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        popup.keypad(1)
        
        # Get recent queries matching this pattern
        queries = list(pattern.recent_queries)
        queries.reverse()  # Most recent first
        
        selected_idx = 0
        scroll_offset = 0
        
        while True:
            popup.clear()
            popup.box()
            
            pattern_short = pattern.fingerprint[:60] + "..." if len(pattern.fingerprint) > 60 else pattern.fingerprint
            title = f" Pattern Queries ({len(queries)} recent) - [↑↓] navigate [Enter] details [ESC] back "
            try:
                popup.attron(curses.color_pair(1) | curses.A_BOLD)
                popup.addstr(0, 2, title[:popup_width - 4])
                popup.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            # Show pattern info
            try:
                popup.attron(curses.A_BOLD)
                popup.addstr(1, 2, f"Pattern: {pattern_short}"[:popup_width - 4])
                popup.attroff(curses.A_BOLD)
            except:
                pass
            
            if not queries:
                try:
                    popup.addstr(popup_height // 2, 2, "No recent queries for this pattern")
                except:
                    pass
                popup.refresh()
                popup.timeout(-1)
                key = popup.getch()
                if key == 27:
                    break
                continue
            
            # Draw query list
            header = f"{'Time':<10} {'Age':<10} {'Host':<20} {'QTime':<10} Query"
            try:
                popup.attron(curses.A_BOLD)
                popup.addstr(3, 2, header[:popup_width - 4])
                popup.attroff(curses.A_BOLD)
            except:
                pass
            
            y = 4
            max_lines = popup_height - 6
            
            visible_start = scroll_offset
            visible_end = min(len(queries), visible_start + max_lines)
            
            for idx, query in enumerate(queries[visible_start:visible_end], start=visible_start):
                if y >= popup_height - 2:
                    break
                
                time_str = query.timestamp[-8:] if len(query.timestamp) >= 8 else query.timestamp
                age_str = self._format_time_ago(query.arrival_time)
                query_time_ms = query.query_time * 1000
                query_str = query.query[:max(1, popup_width - 60)]
                
                line = f"{time_str:<10} {age_str:<10} {query.host:<20} {query_time_ms:<10.1f} {query_str}"
                
                try:
                    if query_time_ms < 100:
                        color = 3
                    elif query_time_ms < 500:
                        color = 4
                    elif query_time_ms < 1000:
                        color = 5
                    else:
                        color = 6
                    
                    if idx == selected_idx:
                        popup.attron(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attron(curses.color_pair(color))
                    
                    popup.addstr(y, 2, line[:popup_width - 4])
                    
                    if idx == selected_idx:
                        popup.attroff(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attroff(curses.color_pair(color))
                except:
                    pass
                y += 1
            
            # Show scroll indicator
            if len(queries) > max_lines:
                try:
                    scroll_info = f" [{scroll_offset + 1}-{min(scroll_offset + max_lines, len(queries))}/{len(queries)}] "
                    popup.addstr(popup_height - 1, popup_width - len(scroll_info) - 2, scroll_info)
                except:
                    pass
            
            popup.refresh()
            popup.timeout(100)
            key = popup.getch()
            
            if key == 27:  # ESC
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                selected_idx = min(len(queries) - 1, selected_idx + 1)
                if selected_idx >= scroll_offset + max_lines:
                    scroll_offset = selected_idx - max_lines + 1
            elif key == 10 or key == curses.KEY_ENTER:
                if 0 <= selected_idx < len(queries):
                    self.show_query_details_popup(stdscr, queries[selected_idx])
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_generic_queries_popup(self, stdscr, title, queries):
        height, width = stdscr.getmaxyx()
        popup_height = height - 4
        popup_width = width - 8
        start_y = 2
        start_x = 4
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        popup.keypad(1)
        queries = list(queries)
        queries.reverse()
        selected_idx = 0
        scroll_offset = 0
        while True:
            popup.clear()
            popup.box()
            popup_title = f" {title} ({len(queries)} queries) - [↑↓] navigate [Enter] details [ESC] back "
            try:
                popup.attron(curses.color_pair(1) | curses.A_BOLD)
                popup.addstr(0, 2, popup_title[:popup_width - 4])
                popup.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            if not queries:
                try:
                    popup.addstr(popup_height // 2, 2, "No queries available")
                except:
                    pass
                popup.refresh()
                popup.timeout(-1)
                key = popup.getch()
                if key == 27:
                    break
                continue
            header = f"{'Time':<10} {'Age':<10} {'Host':<20} {'QTime':<10} Query"
            try:
                popup.attron(curses.A_BOLD)
                popup.addstr(2, 2, header[:popup_width - 4])
                popup.attroff(curses.A_BOLD)
            except:
                pass
            y = 3
            max_lines = popup_height - 5
            visible_start = scroll_offset
            visible_end = min(len(queries), visible_start + max_lines)
            for idx, query in enumerate(queries[visible_start:visible_end], start=visible_start):
                if y >= popup_height - 2:
                    break
                time_str = query.timestamp[-8:] if len(query.timestamp) >= 8 else query.timestamp
                age_str = self._format_time_ago(query.arrival_time)
                query_time_ms = query.query_time * 1000
                query_str = query.query[:max(1, popup_width - 60)]
                line = f"{time_str:<10} {age_str:<10} {query.host:<20} {query_time_ms:<10.1f} {query_str}"
                try:
                    if query_time_ms < 100:
                        color = 3
                    elif query_time_ms < 500:
                        color = 4
                    elif query_time_ms < 1000:
                        color = 5
                    else:
                        color = 6
                    if idx == selected_idx:
                        popup.attron(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attron(curses.color_pair(color))
                    popup.addstr(y, 2, line[:popup_width - 4])
                    if idx == selected_idx:
                        popup.attroff(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attroff(curses.color_pair(color))
                except:
                    pass
                y += 1
            if len(queries) > max_lines:
                try:
                    scroll_info = f" [{scroll_offset + 1}-{min(scroll_offset + max_lines, len(queries))}/{len(queries)}] "
                    popup.addstr(popup_height - 1, popup_width - len(scroll_info) - 2, scroll_info)
                except:
                    pass
            popup.refresh()
            popup.timeout(100)
            key = popup.getch()
            if key == 27:
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                selected_idx = min(len(queries) - 1, selected_idx + 1)
                if selected_idx >= scroll_offset + max_lines:
                    scroll_offset = selected_idx - max_lines + 1
            elif key == 10 or key == curses.KEY_ENTER:
                if 0 <= selected_idx < len(queries):
                    self.show_query_details_popup(stdscr, queries[selected_idx])
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_detailed_stats_popup(self, stdscr):
        """Show recent queries of a specific type"""
        height, width = stdscr.getmaxyx()
        
        popup_height = height - 4
        popup_width = width - 8
        
        start_y = 2
        start_x = 4
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        popup.keypad(1)
        
        # Get recent queries of this type
        queries = [q for q in self.recent_critical if self._get_query_type(q.query) == query_type]
        queries.reverse()  # Most recent first
        
        selected_idx = 0
        scroll_offset = 0
        
        while True:
            popup.clear()
            popup.box()
            
            title = f" {query_type} Queries ({len(queries)} total) - [↑↓] navigate [Enter] details [ESC] back "
            try:
                popup.attron(curses.color_pair(1) | curses.A_BOLD)
                popup.addstr(0, 2, title[:popup_width - 4])
                popup.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            if not queries:
                try:
                    popup.addstr(popup_height // 2, 2, f"No recent {query_type} queries tracked")
                except:
                    pass
                popup.refresh()
                popup.timeout(-1)
                key = popup.getch()
                if key == 27:
                    break
                continue
            
            # Draw query list
            header = f"{'Time':<10} {'Age':<10} {'Host':<20} {'QTime':<10} Query"
            try:
                popup.attron(curses.A_BOLD)
                popup.addstr(2, 2, header[:popup_width - 4])
                popup.attroff(curses.A_BOLD)
            except:
                pass
            
            y = 3
            max_lines = popup_height - 5
            
            visible_start = scroll_offset
            visible_end = min(len(queries), visible_start + max_lines)
            
            for idx, query in enumerate(queries[visible_start:visible_end], start=visible_start):
                if y >= popup_height - 2:
                    break
                
                time_str = query.timestamp[-8:] if len(query.timestamp) >= 8 else query.timestamp
                age_str = self._format_time_ago(query.arrival_time)
                query_time_ms = query.query_time * 1000
                query_str = query.query[:max(1, popup_width - 60)]
                
                line = f"{time_str:<10} {age_str:<10} {query.host:<20} {query_time_ms:<10.1f} {query_str}"
                
                try:
                    if query_time_ms < 100:
                        color = 3
                    elif query_time_ms < 500:
                        color = 4
                    elif query_time_ms < 1000:
                        color = 5
                    else:
                        color = 6
                    
                    if idx == selected_idx:
                        popup.attron(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attron(curses.color_pair(color))
                    
                    popup.addstr(y, 2, line[:popup_width - 4])
                    
                    if idx == selected_idx:
                        popup.attroff(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        popup.attroff(curses.color_pair(color))
                except:
                    pass
                y += 1
            
            # Show scroll indicator
            if len(queries) > max_lines:
                try:
                    scroll_info = f" [{scroll_offset + 1}-{min(scroll_offset + max_lines, len(queries))}/{len(queries)}] "
                    popup.addstr(popup_height - 1, popup_width - len(scroll_info) - 2, scroll_info)
                except:
                    pass
            
            popup.refresh()
            popup.timeout(100)
            key = popup.getch()
            
            if key == 27:  # ESC
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                selected_idx = min(len(queries) - 1, selected_idx + 1)
                if selected_idx >= scroll_offset + max_lines:
                    scroll_offset = selected_idx - max_lines + 1
            elif key == 10 or key == curses.KEY_ENTER:
                if 0 <= selected_idx < len(queries):
                    self.show_query_details_popup(stdscr, queries[selected_idx])
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_detailed_stats_popup(self, stdscr):
        """Show detailed popup for a specific query"""
        height, width = stdscr.getmaxyx()
        
        popup_height = min(height - 4, 35)
        popup_width = min(width - 8, 100)
        
        start_y = (height - popup_height) // 2
        start_x = (width - popup_width) // 2
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        popup.keypad(1)
        
        scroll_offset = 0
        
        while True:
            popup.clear()
            popup.box()
            
            title = " Query Details (ESC to close, ↑↓ scroll) "
            try:
                popup.attron(curses.color_pair(1) | curses.A_BOLD)
                popup.addstr(0, (popup_width - len(title)) // 2, title)
                popup.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            query_time_ms = query.query_time * 1000
            lock_time_ms = query.lock_time * 1000
            age = self._format_time_ago(query.arrival_time)
            
            if query.rows_examined > 0:
                efficiency = (query.rows_sent / query.rows_examined) * 100
            else:
                efficiency = 0
            
            fingerprint = self.fingerprinter.fingerprint(query.query)
            
            content = [
                "",
                "═══ Query Information ═══",
                f"Executed: {age}",
                f"Timestamp: {query.timestamp}",
                f"Host: {query.host}",
                f"User: {query.user}",
                f"Type: {self._get_query_type(query.query)}",
                "",
                "═══ Performance Metrics ═══",
                f"Query Time: {query_time_ms:.2f}ms",
                f"Lock Time: {lock_time_ms:.2f}ms",
                f"Rows Sent: {query.rows_sent:,}",
                f"Rows Examined: {query.rows_examined:,}",
                f"Efficiency: {efficiency:.2f}%",
                "",
            ]
            
            # Add efficiency warning
            if query.rows_examined > 1000 and efficiency < 10:
                content.append("⚠ WARNING: Low efficiency - possible missing index")
                content.append("")
            elif efficiency > 80:
                content.append("✓ Good: High efficiency query")
                content.append("")
            
            content.append("═══ Query Fingerprint ═══")
            wrapped_fp = textwrap.wrap(fingerprint, width=popup_width - 6)
            for line in wrapped_fp:
                content.append(line)
            
            content.append("")
            content.append("═══ Full Query ═══")
            wrapped_query = textwrap.wrap(query.query, width=popup_width - 6)
            for line in wrapped_query:
                content.append(line)
            
            y = 2
            max_lines = popup_height - 4
            
            for line in content[scroll_offset:scroll_offset + max_lines]:
                if y >= popup_height - 2:
                    break
                
                try:
                    if "⚠" in line or "WARNING" in line:
                        popup.attron(curses.color_pair(6))
                        popup.addstr(y, 2, line[:popup_width - 4])
                        popup.attroff(curses.color_pair(6))
                    elif "✓" in line:
                        popup.attron(curses.color_pair(3))
                        popup.addstr(y, 2, line[:popup_width - 4])
                        popup.attroff(curses.color_pair(3))
                    elif line.startswith("═"):
                        popup.attron(curses.A_BOLD)
                        popup.addstr(y, 2, line[:popup_width - 4])
                        popup.attroff(curses.A_BOLD)
                    else:
                        popup.addstr(y, 2, line[:popup_width - 4])
                except:
                    pass
                y += 1
            
            if len(content) > max_lines:
                try:
                    scroll_info = f" [{scroll_offset + 1}-{min(scroll_offset + max_lines, len(content))}/{len(content)}] "
                    popup.addstr(popup_height - 1, popup_width - len(scroll_info) - 2, scroll_info)
                except:
                    pass
            
            popup.refresh()
            popup.timeout(100)
            key = popup.getch()
            
            if key == 27 or key == ord('q'):
                break
            elif key == curses.KEY_UP:
                scroll_offset = max(0, scroll_offset - 1)
            elif key == curses.KEY_DOWN:
                scroll_offset = min(len(content) - max_lines, scroll_offset + 1)
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_detailed_stats_popup(self, stdscr):
        """Show detailed system statistics"""
        height, width = stdscr.getmaxyx()
        
        popup_height = min(height - 4, 25)
        popup_width = min(width - 8, 70)
        
        start_y = (height - popup_height) // 2
        start_x = (width - popup_width) // 2
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        
        title = " Detailed Statistics (ESC to close) "
        try:
            popup.attron(curses.color_pair(1) | curses.A_BOLD)
            popup.addstr(0, (popup_width - len(title)) // 2, title)
            popup.attroff(curses.color_pair(1) | curses.A_BOLD)
        except:
            pass
        
        current_time = time.time()
        uptime = current_time - self.start_time if self.start_time else 0
        
        # Calculate stats
        total_patterns = len(self.query_patterns)
        total_hosts = len(self.host_latency)
        total_users = len(set(hu.split('@')[1] for hu in self.host_user_latency.keys() if '@' in hu))
        
        recent = list(self.recent_critical)
        slow_1m = sum(1 for q in recent if current_time - q.arrival_time < 60 and q.query_time * 1000 > 1000)
        slow_5m = sum(1 for q in recent if current_time - q.arrival_time < 300 and q.query_time * 1000 > 1000)
        
        avg_qps = self.total_queries / max(uptime, 1)
        max_qps = max(self.qps_history) if self.qps_history else 0
        
        mem_mb = self._get_memory_usage()
        
        content = [
            "",
            "═══ System Information ═══",
            f"Uptime: {int(uptime)}s ({int(uptime/60)}m)",
            f"Memory Usage: {mem_mb:.1f} MB",
            f"Log File: {self.log_path.name}",
            f"Refresh Rate: {self.refresh_rate}s",
            "",
            "═══ Query Statistics ═══",
            f"Total Queries: {self.total_queries:,}",
            f"Parse Errors: {self.parse_errors}",
            f"Average QPS: {avg_qps:.1f}",
            f"Peak QPS: {max_qps:.1f}",
            "",
            "═══ Slow Query Analysis ═══",
            f"Tracked Slow: {len(recent):,}",
            f"Slow (1m): {slow_1m}",
            f"Slow (5m): {slow_5m}",
            "",
            "═══ Patterns & Sources ═══",
            f"Query Patterns: {total_patterns}",
            f"Unique Hosts: {total_hosts}",
            f"Unique Users: {total_users}",
            f"Host+User Combos: {len(self.host_user_latency)}",
        ]
        
        y = 2
        for line in content:
            if y >= popup_height - 2:
                break
            
            try:
                if line.startswith("═"):
                    popup.attron(curses.A_BOLD | curses.color_pair(3))
                    popup.addstr(y, 2, line[:popup_width - 4])
                    popup.attroff(curses.A_BOLD | curses.color_pair(3))
                else:
                    popup.addstr(y, 2, line[:popup_width - 4])
            except:
                pass
            y += 1
        
        popup.refresh()
        popup.timeout(-1)
        popup.getch()
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def export_current_view(self, stdscr):
        """Export current view to file"""
        height, width = stdscr.getmaxyx()
        
        popup_height = 10
        popup_width = 60
        
        start_y = (height - popup_height) // 2
        start_x = (width - popup_width) // 2
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        
        title = " Export Current View "
        try:
            popup.attron(curses.color_pair(1) | curses.A_BOLD)
            popup.addstr(0, (popup_width - len(title)) // 2, title)
            popup.attroff(curses.color_pair(1) | curses.A_BOLD)
        except:
            pass
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        view_names = ["global", "hosts", "query_types", "recent", "patterns"]
        filename_csv = f"slowmon_{view_names[self.view_mode]}_{timestamp}.csv"
        filename_json = f"slowmon_{view_names[self.view_mode]}_{timestamp}.json"
        
        try:
            popup.addstr(2, 2, "Select export format:")
            popup.addstr(4, 4, "[1] CSV")
            popup.addstr(5, 4, "[2] JSON")
            popup.addstr(7, 2, "Press ESC to cancel")
        except:
            pass
        
        popup.refresh()
        popup.timeout(-1)
        key = popup.getch()
        
        if key == ord('1'):
            # Export as CSV
            try:
                self._export_csv(filename_csv)
                msg = f"Exported to: {filename_csv}"
                color = 3
            except Exception as e:
                msg = f"Export failed: {str(e)}"
                color = 6
        elif key == ord('2'):
            # Export as JSON
            try:
                self._export_json(filename_json)
                msg = f"Exported to: {filename_json}"
                color = 3
            except Exception as e:
                msg = f"Export failed: {str(e)}"
                color = 6
        else:
            msg = "Export cancelled"
            color = 4
        
        # Show result
        popup.clear()
        popup.box()
        try:
            popup.attron(curses.color_pair(color))
            popup.addstr(popup_height // 2, 2, msg[:popup_width - 4])
            popup.attroff(curses.color_pair(color))
            popup.addstr(popup_height - 2, 2, "Press any key to continue")
        except:
            pass
        popup.refresh()
        popup.getch()
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def _export_csv(self, filename):
        """Export current view data to CSV"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            if self.view_mode == 3:  # Recent queries
                writer.writerow(['Timestamp', 'Host', 'User', 'Query Time (ms)', 'Query'])
                for q in reversed(list(self.recent_critical)):
                    writer.writerow([q.timestamp, q.host, q.user, q.query_time * 1000, q.query])
            
            elif self.view_mode == 4:  # Patterns
                writer.writerow(['Count', 'Avg Time (ms)', 'Total Time (s)', 'Efficiency %', 'Hosts', 'Pattern'])
                for pattern in self.query_patterns.values():
                    writer.writerow([
                        pattern.count,
                        pattern.avg_time * 1000,
                        pattern.total_time,
                        pattern.efficiency,
                        len(pattern.hosts),
                        pattern.fingerprint
                    ])
    
    def _export_json(self, filename):
        """Export current view data to JSON"""
        data = {
            'exported_at': datetime.now().isoformat(),
            'view': self.view_mode,
            'total_queries': self.total_queries,
            'data': []
        }
        
        if self.view_mode == 3:  # Recent queries
            for q in reversed(list(self.recent_critical)):
                data['data'].append({
                    'timestamp': q.timestamp,
                    'host': q.host,
                    'user': q.user,
                    'query_time_ms': q.query_time * 1000,
                    'query': q.query
                })
        
        elif self.view_mode == 4:  # Patterns
            for pattern in self.query_patterns.values():
                data['data'].append({
                    'count': pattern.count,
                    'avg_time_ms': pattern.avg_time * 1000,
                    'total_time_s': pattern.total_time,
                    'efficiency': pattern.efficiency,
                    'hosts': list(pattern.hosts),
                    'pattern': pattern.fingerprint
                })
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def show_search_dialog(self, stdscr):
        """Show search input dialog"""
        height, width = stdscr.getmaxyx()
        
        dialog_height = 7
        dialog_width = 60
        
        start_y = (height - dialog_height) // 2
        start_x = (width - dialog_width) // 2
        
        dialog = curses.newwin(dialog_height, dialog_width, start_y, start_x)
        dialog.keypad(1)
        dialog.box()
        
        title = " Search "
        try:
            dialog.attron(curses.color_pair(1) | curses.A_BOLD)
            dialog.addstr(0, (dialog_width - len(title)) // 2, title)
            dialog.attroff(curses.color_pair(1) | curses.A_BOLD)
        except:
            pass
        
        search_text = ""
        
        while True:
            dialog.clear()
            dialog.box()
            
            try:
                dialog.addstr(0, (dialog_width - len(title)) // 2, title)
                dialog.addstr(2, 2, "Enter search term (ESC to cancel):")
                dialog.attron(curses.A_REVERSE)
                display = f" {search_text} ".ljust(dialog_width - 4)
                dialog.addstr(3, 2, display)
                dialog.attroff(curses.A_REVERSE)
            except:
                pass
            
            dialog.refresh()
            dialog.timeout(-1)
            key = dialog.getch()
            
            if key == 27:  # ESC
                del dialog
                stdscr.touchwin()
                stdscr.refresh()
                return None
            elif key == 10 or key == curses.KEY_ENTER:
                del dialog
                stdscr.touchwin()
                stdscr.refresh()
                return search_text
            elif key == curses.KEY_BACKSPACE or key == 127 or key == 8:
                search_text = search_text[:-1]
            elif 32 <= key < 127:
                if len(search_text) < 50:
                    search_text += chr(key)
    
    def show_help_popup(self, stdscr):
        """Show context-sensitive help based on current view"""
        height, width = stdscr.getmaxyx()
        
        popup_height = min(height - 4, 30)
        popup_width = min(width - 8, 80)
        
        start_y = (height - popup_height) // 2
        start_x = (width - popup_width) // 2
        
        popup = curses.newwin(popup_height, popup_width, start_y, start_x)
        popup.box()
        
        view_names = ["GLOBAL", "HOST", "QUERY TYPE", "RECENT", "PATTERNS"]
        title = f" Help: {view_names[self.view_mode]} View (ESC to close) "
        
        try:
            popup.attron(curses.color_pair(1) | curses.A_BOLD)
            popup.addstr(0, (popup_width - len(title)) // 2, title)
            popup.attroff(curses.color_pair(1) | curses.A_BOLD)
        except:
            pass
        
        help_text = self._get_help_for_view()
        
        y = 2
        for line in help_text:
            if y >= popup_height - 2:
                break
            try:
                if line.startswith(">>"):
                    popup.attron(curses.color_pair(3) | curses.A_BOLD)
                    popup.addstr(y, 2, line[2:][:popup_width - 4])
                    popup.attroff(curses.color_pair(3) | curses.A_BOLD)
                else:
                    popup.addstr(y, 2, line[:popup_width - 4])
            except:
                pass
            y += 1
        
        popup.refresh()
        popup.timeout(-1)
        popup.getch()
        
        del popup
        stdscr.touchwin()
        stdscr.refresh()
    
    def _get_help_for_view(self):
        """Return help text for current view"""
        common = [
            "",
            "Common Keys:",
            "[1-7] Switch views  [p] Pause",
            "[e] Export  [d] Stats  [/] Search",
            "[?] Help  [q] Quit",
        ]
        
        if self.view_mode == 0:
            return [
                ">> GLOBAL LATENCY DISTRIBUTION",
                "",
                "Shows overall query performance.",
                "Time windows: 10s, 1m, 10m, 1h, 6h",
                "",
                "Latency buckets:",
                "  <10ms, <100ms, <500ms, <1s, >1s",
            ] + common
        
        elif self.view_mode == 1:
            return [
                ">> BY HOST + USER VIEW",
                "",
                "Groups queries by host and user.",
                "[Enter] Select host to view queries",
                "[s] Cycle sort modes",
                "[↑↓] Scroll",
                "",
                "Press Enter to open a selector, choose",
                "a host, then browse and view individual",
                "query details.",
            ] + common
        
        elif self.view_mode == 2:
            return [
                ">> BY QUERY TYPE VIEW",
                "",
                "Groups by SQL command type.",
                "[Enter] Select type to view queries",
                "[s] Cycle sort modes",
                "[↑↓] Scroll",
                "",
                "Press Enter to open a selector, choose",
                "a query type, then browse and view",
                "individual query details.",
            ] + common
        
        elif self.view_mode == 3:
            return [
                ">> RECENT SLOW QUERIES",
                "",
                "Shows individual slow queries (>100ms).",
                "[↑↓] Navigate  [Enter] View details",
                "",
                "Color coding:",
                "  Green <100ms  Yellow <500ms",
                "  Magenta <1s   Red >1s",
            ] + common
        
        elif self.view_mode == 4:
            return [
                ">> QUERY PATTERN ANALYSIS",
                "",
                "Normalized query patterns.",
                "[↑↓] Navigate  [Enter] View queries",
                "[f] Filter by host  [c] Clear filter",
                "[s] Cycle sort modes",
                "",
                "Press Enter to see recent queries",
                "matching the selected pattern, then",
                "drill down to individual query details.",
            ] + common
        
        elif self.view_mode == 5:
            return [
                ">> DATABASE/TABLE BREAKDOWN",
                "",
                "Shows query statistics by database",
                "and table.",
                "[Tab] Toggle between DB and Table view",
                "[↑↓] Navigate  [Enter] View queries",
                "[s] Cycle sort modes",
                "",
                "Sort by: Name, Count, Avg Time,",
                "Total Time, or Lock Time",
            ] + common
        
        elif self.view_mode == 6:
            return [
                ">> LOCK CONTENTION ANALYSIS",
                "",
                "Shows queries with high lock times",
                "(>100ms lock wait).",
                "[↑↓] Navigate  [Enter] View details",
                "[s] Cycle sort modes",
                "",
                "Use this to identify queries causing",
                "locking issues and table contention.",
                "",
                "Color: Yellow <500ms, Magenta <1s, Red >1s",
            ] + common
        
        return common
    
    def show_pattern_filter_dialog(self, stdscr):
        """Show dialog to filter patterns by host"""
        height, width = stdscr.getmaxyx()
        
        dialog_height = 15
        dialog_width = 70
        
        start_y = (height - dialog_height) // 2
        start_x = (width - dialog_width) // 2
        
        dialog = curses.newwin(dialog_height, dialog_width, start_y, start_x)
        dialog.keypad(1)
        
        all_hosts = set()
        for pattern in self.query_patterns.values():
            all_hosts.update(pattern.hosts)
        all_hosts = sorted(all_hosts)
        
        selected_idx = 0
        scroll_offset = 0
        
        while True:
            dialog.clear()
            dialog.box()
            
            title = " Filter Patterns by Host "
            try:
                dialog.attron(curses.color_pair(1) | curses.A_BOLD)
                dialog.addstr(0, (dialog_width - len(title)) // 2, title)
                dialog.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            try:
                dialog.addstr(2, 2, "Select a host to filter patterns:")
                dialog.addstr(3, 2, "(Press Enter to select, 'a' for All, ESC to cancel)")
                
                y = 5
                max_display = dialog_height - 7
                
                if selected_idx == 0:
                    dialog.attron(curses.A_REVERSE)
                dialog.addstr(y, 4, "[ All Hosts ]")
                if selected_idx == 0:
                    dialog.attroff(curses.A_REVERSE)
                y += 1
                
                display_hosts = all_hosts[scroll_offset:scroll_offset + max_display - 1]
                for idx, host in enumerate(display_hosts, start=1):
                    if y >= dialog_height - 2:
                        break
                    
                    if selected_idx == idx:
                        dialog.attron(curses.A_REVERSE)
                    
                    display_text = f"  {host}"[:dialog_width - 6]
                    dialog.addstr(y, 4, display_text)
                    
                    if selected_idx == idx:
                        dialog.attroff(curses.A_REVERSE)
                    y += 1
                
                if len(all_hosts) > max_display - 1:
                    info = f"[{scroll_offset + 1}-{min(scroll_offset + max_display - 1, len(all_hosts))}/{len(all_hosts)}]"
                    dialog.addstr(dialog_height - 2, dialog_width - len(info) - 2, info)
            except:
                pass
            
            dialog.refresh()
            
            dialog.timeout(-1)
            key = dialog.getch()
            
            if key == 27:
                break
            elif key == ord('a') or key == ord('A'):
                self.pattern_filter_host = ""
                self.pattern_filter_active = False
                self.data_changed = True
                break
            elif key == 10 or key == curses.KEY_ENTER:
                if selected_idx == 0:
                    self.pattern_filter_host = ""
                    self.pattern_filter_active = False
                else:
                    actual_idx = scroll_offset + selected_idx - 1
                    if actual_idx < len(all_hosts):
                        self.pattern_filter_host = all_hosts[actual_idx]
                        self.pattern_filter_active = True
                self.data_changed = True
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                max_idx = min(len(all_hosts), dialog_height - 7)
                selected_idx = min(len(all_hosts), selected_idx + 1)
                if selected_idx > scroll_offset + max_idx - 1:
                    scroll_offset = selected_idx - max_idx + 1
        
        del dialog
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_host_selector_dialog(self, stdscr):
        """Show dialog to select a host to view queries from"""
        height, width = stdscr.getmaxyx()
        
        dialog_height = min(height - 4, 20)
        dialog_width = 70
        
        start_y = (height - dialog_height) // 2
        start_x = (width - dialog_width) // 2
        
        dialog = curses.newwin(dialog_height, dialog_width, start_y, start_x)
        dialog.keypad(1)
        
        # Get sorted list of hosts
        host_users = list(self.host_user_latency.keys())
        if self.host_sort_mode == 0:
            host_users.sort()
        elif self.host_sort_mode == 1:
            current_time = time.time()
            host_query_counts = {}
            for hu in host_users:
                total = 0
                for threshold in [10, 100, 500, 1000, float('inf')]:
                    bucket = self.host_user_latency[hu][threshold]
                    counts = bucket.get_counts(current_time)
                    total += counts[10]
                host_query_counts[hu] = total
            host_users.sort(key=lambda h: host_query_counts.get(h, 0), reverse=True)
        elif self.host_sort_mode == 2:
            current_time = time.time()
            host_slow_counts = {}
            for hu in host_users:
                total = 0
                for threshold in [100, 500, 1000, float('inf')]:
                    bucket = self.host_user_latency[hu][threshold]
                    counts = bucket.get_counts(current_time)
                    total += counts[10]
                host_slow_counts[hu] = total
            host_users.sort(key=lambda h: host_slow_counts.get(h, 0), reverse=True)
        
        selected_idx = 0
        scroll_offset = 0
        
        while True:
            dialog.clear()
            dialog.box()
            
            title = " Select Host to View Queries "
            try:
                dialog.attron(curses.color_pair(1) | curses.A_BOLD)
                dialog.addstr(0, (dialog_width - len(title)) // 2, title)
                dialog.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            try:
                dialog.addstr(2, 2, "Select a host to view its queries:")
                dialog.addstr(3, 2, "(Press Enter to select, ESC to cancel)")
                
                y = 5
                max_display = dialog_height - 7
                
                display_hosts = host_users[scroll_offset:scroll_offset + max_display]
                for idx, host_user in enumerate(display_hosts, start=scroll_offset):
                    if y >= dialog_height - 2:
                        break
                    
                    if idx == selected_idx:
                        dialog.attron(curses.A_REVERSE)
                    
                    display_text = f"  {host_user}"[:dialog_width - 6]
                    dialog.addstr(y, 4, display_text)
                    
                    if idx == selected_idx:
                        dialog.attroff(curses.A_REVERSE)
                    y += 1
                
                if len(host_users) > max_display:
                    info = f"[{scroll_offset + 1}-{min(scroll_offset + max_display, len(host_users))}/{len(host_users)}]"
                    dialog.addstr(dialog_height - 2, dialog_width - len(info) - 2, info)
            except:
                pass
            
            dialog.refresh()
            
            dialog.timeout(-1)
            key = dialog.getch()
            
            if key == 27:
                break
            elif key == 10 or key == curses.KEY_ENTER:
                if 0 <= selected_idx < len(host_users):
                    selected_host = host_users[selected_idx]
                    dialog.clear()
                    del dialog
                    stdscr.touchwin()
                    self.show_host_queries_popup(stdscr, selected_host)
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                selected_idx = min(len(host_users) - 1, selected_idx + 1)
                if selected_idx >= scroll_offset + (dialog_height - 7):
                    scroll_offset = selected_idx - (dialog_height - 7) + 1
        
        del dialog
        stdscr.touchwin()
        stdscr.refresh()
    
    def show_query_type_selector_dialog(self, stdscr):
        """Show dialog to select a query type to view queries from"""
        height, width = stdscr.getmaxyx()
        
        dialog_height = min(height - 4, 20)
        dialog_width = 50
        
        start_y = (height - dialog_height) // 2
        start_x = (width - dialog_width) // 2
        
        dialog = curses.newwin(dialog_height, dialog_width, start_y, start_x)
        dialog.keypad(1)
        
        # Get sorted list of query types
        query_types = list(self.query_type_latency.keys())
        if self.qtype_sort_mode == 0:
            query_types.sort()
        elif self.qtype_sort_mode == 1:
            current_time = time.time()
            type_query_counts = {}
            for qtype in query_types:
                total = 0
                for threshold in [10, 100, 500, 1000, float('inf')]:
                    bucket = self.query_type_latency[qtype][threshold]
                    counts = bucket.get_counts(current_time)
                    total += counts[10]
                type_query_counts[qtype] = total
            query_types.sort(key=lambda q: type_query_counts.get(q, 0), reverse=True)
        elif self.qtype_sort_mode == 2:
            current_time = time.time()
            type_slow_counts = {}
            for qtype in query_types:
                total = 0
                for threshold in [100, 500, 1000, float('inf')]:
                    bucket = self.query_type_latency[qtype][threshold]
                    counts = bucket.get_counts(current_time)
                    total += counts[10]
                type_slow_counts[qtype] = total
            query_types.sort(key=lambda q: type_slow_counts.get(q, 0), reverse=True)
        
        selected_idx = 0
        scroll_offset = 0
        
        while True:
            dialog.clear()
            dialog.box()
            
            title = " Select Query Type "
            try:
                dialog.attron(curses.color_pair(1) | curses.A_BOLD)
                dialog.addstr(0, (dialog_width - len(title)) // 2, title)
                dialog.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            try:
                dialog.addstr(2, 2, "Select a type to view its queries:")
                dialog.addstr(3, 2, "(Press Enter to select, ESC to cancel)")
                
                y = 5
                max_display = dialog_height - 7
                
                display_types = query_types[scroll_offset:scroll_offset + max_display]
                for idx, qtype in enumerate(display_types, start=scroll_offset):
                    if y >= dialog_height - 2:
                        break
                    
                    if idx == selected_idx:
                        dialog.attron(curses.A_REVERSE)
                    
                    display_text = f"  {qtype}"[:dialog_width - 6]
                    dialog.addstr(y, 4, display_text)
                    
                    if idx == selected_idx:
                        dialog.attroff(curses.A_REVERSE)
                    y += 1
                
                if len(query_types) > max_display:
                    info = f"[{scroll_offset + 1}-{min(scroll_offset + max_display, len(query_types))}/{len(query_types)}]"
                    dialog.addstr(dialog_height - 2, dialog_width - len(info) - 2, info)
            except:
                pass
            
            dialog.refresh()
            
            dialog.timeout(-1)
            key = dialog.getch()
            
            if key == 27:
                break
            elif key == 10 or key == curses.KEY_ENTER:
                if 0 <= selected_idx < len(query_types):
                    selected_type = query_types[selected_idx]
                    dialog.clear()
                    del dialog
                    stdscr.touchwin()
                    self.show_query_type_queries_popup(stdscr, selected_type)
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                selected_idx = min(len(query_types) - 1, selected_idx + 1)
                if selected_idx >= scroll_offset + (dialog_height - 7):
                    scroll_offset = selected_idx - (dialog_height - 7) + 1
        
        del dialog
        stdscr.touchwin()
        stdscr.refresh()
    
    def _draw_sparkline(self, data, width, cache_key=None):
        """Show dialog to filter patterns by host"""
        height, width = stdscr.getmaxyx()
        
        dialog_height = 15
        dialog_width = 70
        
        start_y = (height - dialog_height) // 2
        start_x = (width - dialog_width) // 2
        
        dialog = curses.newwin(dialog_height, dialog_width, start_y, start_x)
        dialog.keypad(1)
        
        all_hosts = set()
        for pattern in self.query_patterns.values():
            all_hosts.update(pattern.hosts)
        all_hosts = sorted(all_hosts)
        
        selected_idx = 0
        scroll_offset = 0
        
        while True:
            dialog.clear()
            dialog.box()
            
            title = " Filter Patterns by Host "
            try:
                dialog.attron(curses.color_pair(1) | curses.A_BOLD)
                dialog.addstr(0, (dialog_width - len(title)) // 2, title)
                dialog.attroff(curses.color_pair(1) | curses.A_BOLD)
            except:
                pass
            
            try:
                dialog.addstr(2, 2, "Select a host to filter patterns:")
                dialog.addstr(3, 2, "(Press Enter to select, 'a' for All, ESC to cancel)")
                
                y = 5
                max_display = dialog_height - 7
                
                if selected_idx == 0:
                    dialog.attron(curses.A_REVERSE)
                dialog.addstr(y, 4, "[ All Hosts ]")
                if selected_idx == 0:
                    dialog.attroff(curses.A_REVERSE)
                y += 1
                
                display_hosts = all_hosts[scroll_offset:scroll_offset + max_display - 1]
                for idx, host in enumerate(display_hosts, start=1):
                    if y >= dialog_height - 2:
                        break
                    
                    if selected_idx == idx:
                        dialog.attron(curses.A_REVERSE)
                    
                    display_text = f"  {host}"[:dialog_width - 6]
                    dialog.addstr(y, 4, display_text)
                    
                    if selected_idx == idx:
                        dialog.attroff(curses.A_REVERSE)
                    y += 1
                
                if len(all_hosts) > max_display - 1:
                    info = f"[{scroll_offset + 1}-{min(scroll_offset + max_display - 1, len(all_hosts))}/{len(all_hosts)}]"
                    dialog.addstr(dialog_height - 2, dialog_width - len(info) - 2, info)
            except:
                pass
            
            dialog.refresh()
            
            dialog.timeout(-1)
            key = dialog.getch()
            
            if key == 27:
                break
            elif key == ord('a') or key == ord('A'):
                self.pattern_filter_host = ""
                self.pattern_filter_active = False
                self.data_changed = True
                break
            elif key == 10 or key == curses.KEY_ENTER:
                if selected_idx == 0:
                    self.pattern_filter_host = ""
                    self.pattern_filter_active = False
                else:
                    actual_idx = scroll_offset + selected_idx - 1
                    if actual_idx < len(all_hosts):
                        self.pattern_filter_host = all_hosts[actual_idx]
                        self.pattern_filter_active = True
                self.data_changed = True
                break
            elif key == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
            elif key == curses.KEY_DOWN:
                max_idx = min(len(all_hosts), dialog_height - 7)
                selected_idx = min(len(all_hosts), selected_idx + 1)
                if selected_idx > scroll_offset + max_idx - 1:
                    scroll_offset = selected_idx - max_idx + 1
        
        del dialog
        stdscr.touchwin()
        stdscr.refresh()
    
    def _draw_sparkline(self, data, width, cache_key=None):
        """Generate ASCII sparkline with caching - Fixed for all zeros"""
        current_time = time.time()
        
        if cache_key and cache_key in self._sparkline_cache:
            cached_spark, cache_time = self._sparkline_cache[cache_key]
            if current_time - cache_time < 1.0:
                return cached_spark
        
        if not data or len(data) < 2:
            result = "─" * width
        else:
            data_subset = list(data)[-width:]
            
            if not data_subset:
                result = "─" * width
            else:
                min_val = min(data_subset)
                max_val = max(data_subset)
                
                if max_val == min_val:
                    if max_val == 0:
                        result = "▁" * len(data_subset)
                    else:
                        result = "▄" * len(data_subset)
                else:
                    sparks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']
                    
                    sparkline = ""
                    for val in data_subset:
                        normalized = (val - min_val) / (max_val - min_val)
                        idx = int(normalized * (len(sparks) - 1))
                        sparkline += sparks[idx]
                    
                    result = sparkline
        
        if cache_key:
            self._sparkline_cache[cache_key] = (result, current_time)
        
        return result
    
    def draw_global_view(self, stdscr, height, width, y):
        current_time = time.time()
        
        try:
            stdscr.attron(curses.A_BOLD)
            stdscr.addstr(y, 0, "Trends (last 60 intervals)"[:width - 1])
            stdscr.attroff(curses.A_BOLD)
        except:
            pass
        y += 1
        
        if y >= height - 3:
            return
        
        sparkline_width = min(60, width - 30)
        qps_sparkline = self._draw_sparkline(self.qps_history, sparkline_width, 'global_qps') if len(self.qps_history) >= 2 else "─" * 20 + " (collecting...)"
        qps_current = self.qps_history[-1] if self.qps_history else 0
        qps_max = max(self.qps_history) if self.qps_history else 0
        
        try:
            stdscr.attron(curses.color_pair(3))
            line = f"QPS:  {qps_sparkline} cur:{qps_current:.0f} max:{qps_max:.0f}"
            stdscr.addstr(y, 0, line[:width - 1])
            stdscr.attroff(curses.color_pair(3))
        except:
            pass
        y += 1
        
        if y >= height - 3:
            return
        
        slow_sparkline = self._draw_sparkline(self.slow_query_history, sparkline_width, 'global_slow') if len(self.slow_query_history) >= 2 else "─" * 20 + " (collecting...)"
        slow_current = self.slow_query_history[-1] if self.slow_query_history else 0
        slow_max = max(self.slow_query_history) if self.slow_query_history else 0
        
        try:
            stdscr.attron(curses.color_pair(6))
            line = f"Slow: {slow_sparkline} cur:{slow_current} max:{slow_max}"
            stdscr.addstr(y, 0, line[:width - 1])
            stdscr.attroff(curses.color_pair(6))
        except:
            pass
        y += 2
        
        if y >= height - 3:
            return
        
        stdscr.attron(curses.A_BOLD)
        try:
            stdscr.addstr(y, 0, "Global Latency Distribution"[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        if y >= height - 3:
            return
        
        header = f"{'Latency':<12} {'10s':<10} {'1m':<10} {'10m':<10} {'1h':<10} {'6h':<10}"
        stdscr.attron(curses.A_BOLD)
        try:
            stdscr.addstr(y, 0, header[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        latency_labels = {10: "< 10ms", 100: "< 100ms", 500: "< 500ms", 1000: "< 1000ms", float('inf'): "> 1000ms"}
        color_map = {10: 2, 100: 3, 500: 4, 1000: 5, float('inf'): 6}
        
        show_windows = {
            10: self._should_show_time_window(10),
            60: self._should_show_time_window(60),
            600: self._should_show_time_window(600),
            3600: self._should_show_time_window(3600),
            21600: self._should_show_time_window(21600)
        }
        
        for threshold in [10, 100, 500, 1000, float('inf')]:
            if y >= height - 3:
                break
            
            bucket = self.latency_buckets[threshold]
            counts = bucket.get_counts(current_time)
            
            val_10s = str(counts[10]) if show_windows[10] else "-"
            val_1m = str(counts[60]) if show_windows[60] else "-"
            val_10m = str(counts[600]) if show_windows[600] else "-"
            val_1h = str(counts[3600]) if show_windows[3600] else "-"
            val_6h = str(counts[21600]) if show_windows[21600] else "-"
            
            line = f"{latency_labels[threshold]:<12} {val_10s:<10} {val_1m:<10} {val_10m:<10} {val_1h:<10} {val_6h:<10}"
            
            try:
                stdscr.attron(curses.color_pair(color_map[threshold]))
                stdscr.addstr(y, 0, line[:width - 1])
                stdscr.attroff(curses.color_pair(color_map[threshold]))
            except:
                pass
            y += 1
    
    def draw_host_view(self, stdscr, height, width, y):
        current_time = time.time()
        
        if not self.host_user_latency:
            try:
                stdscr.addstr(y, 0, "No host data yet...")
            except:
                pass
            return
        
        sort_modes = ["Alphabetical", "QPS (High→Low)", "Slow Queries (High→Low)"]
        stdscr.attron(curses.A_BOLD)
        try:
            title = f"Latency Distribution by Host + User - [s]ort [Enter] view queries"
            stdscr.addstr(y, 0, title[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        start_y = y
        
        min_col_width = 48
        num_columns = max(1, width // min_col_width)
        col_width = width // num_columns
        
        host_users = list(self.host_user_latency.keys())
        
        if self.host_sort_mode == 0:
            host_users.sort()
        elif self.host_sort_mode == 1:
            host_query_counts = {}
            for hu in host_users:
                total = 0
                for threshold in [10, 100, 500, 1000, float('inf')]:
                    bucket = self.host_user_latency[hu][threshold]
                    counts = bucket.get_counts(current_time)
                    total += counts[10]
                host_query_counts[hu] = total
            host_users.sort(key=lambda h: host_query_counts.get(h, 0), reverse=True)
        elif self.host_sort_mode == 2:
            host_slow_counts = {}
            for hu in host_users:
                total = 0
                for threshold in [100, 500, 1000, float('inf')]:
                    bucket = self.host_user_latency[hu][threshold]
                    counts = bucket.get_counts(current_time)
                    total += counts[10]
                host_slow_counts[hu] = total
            host_users.sort(key=lambda h: host_slow_counts.get(h, 0), reverse=True)
        
        host_users_to_show = host_users[self.scroll_offset:]
        
        rows_per_host = 9
        max_rows = height - y - 2
        hosts_per_column = max_rows // rows_per_host
        
        for col_idx in range(num_columns):
            x_offset = col_idx * col_width
            start_idx = col_idx * hosts_per_column
            end_idx = start_idx + hosts_per_column
            column_hosts = host_users_to_show[start_idx:end_idx]
            
            y = start_y
            for host_user in column_hosts:
                if y >= height - 2:
                    break
                y = self._draw_host_user_table(stdscr, y, x_offset, col_width, host_user, current_time)
    
    def _draw_host_user_table(self, stdscr, y, x_offset, col_width, host_user, current_time):
        max_y = stdscr.getmaxyx()[0]
        
        if y >= max_y - 2:
            return y
        
        if '@' in host_user:
            host_part, user_part = host_user.rsplit('@', 1)
        else:
            host_part = host_user
            user_part = ""
        
        host_user_count = 0
        total_count = 0
        for hu in self.host_user_latency.keys():
            for threshold in [10, 100, 500, 1000, float('inf')]:
                bucket = self.host_user_latency[hu][threshold]
                counts = bucket.get_counts(current_time)
                count_10s = counts[10]
                total_count += count_10s
                if hu == host_user:
                    host_user_count += count_10s
        
        if total_count > 0:
            percentage = (host_user_count / total_count) * 100
        else:
            percentage = 0
        
        try:
            stdscr.attron(curses.A_BOLD)
            stdscr.addstr(y, x_offset, host_part[:col_width - len(user_part) - 10])
            stdscr.attroff(curses.A_BOLD)
            
            if user_part:
                user_display = f" {user_part} {percentage:.1f}%"
                current_x = x_offset + len(host_part)
                if current_x + len(user_display) < x_offset + col_width - 1:
                    stdscr.attron(curses.color_pair(7))
                    stdscr.addstr(y, current_x, user_display[:col_width - len(host_part) - 1])
                    stdscr.attroff(curses.color_pair(7))
        except:
            pass
        y += 1
        
        if y >= max_y - 2:
            return y
        
        sparkline_width = min(25, col_width - 15)
        
        qps_history = self.host_qps_history.get(host_part, deque())
        if len(qps_history) >= 2:
            qps_spark = self._draw_sparkline(qps_history, sparkline_width, f'host_qps_{host_part}')
            qps_cur = qps_history[-1] if qps_history else 0
            try:
                stdscr.attron(curses.color_pair(3))
                line = f"QPS:{qps_spark} {qps_cur:.0f}/s"
                stdscr.addstr(y, x_offset, line[:col_width - 1])
                stdscr.attroff(curses.color_pair(3))
            except:
                pass
            y += 1
        
        if y >= max_y - 2:
            return y
        
        slow_history = self.host_slow_history.get(host_part, deque())
        if len(slow_history) >= 2:
            slow_spark = self._draw_sparkline(slow_history, sparkline_width, f'host_slow_{host_part}')
            slow_cur = slow_history[-1] if slow_history else 0
            try:
                stdscr.attron(curses.color_pair(6))
                line = f"Slw:{slow_spark} {slow_cur}"
                stdscr.addstr(y, x_offset, line[:col_width - 1])
                stdscr.attroff(curses.color_pair(6))
            except:
                pass
            y += 1
        
        if y >= max_y - 2:
            return y
        
        header = f"{'Latency':<10} {'10s':<12} {'1m':<12} {'10m':<12}"
        try:
            stdscr.attron(curses.A_BOLD)
            stdscr.addstr(y, x_offset, header[:col_width - 1])
            stdscr.attroff(curses.A_BOLD)
        except:
            pass
        y += 1
        
        show_windows = {
            10: self._should_show_time_window(10),
            60: self._should_show_time_window(60),
            600: self._should_show_time_window(600)
        }
        
        latency_labels = {10: "<10ms", 100: "<100ms", 500: "<500ms", 1000: "<1s", float('inf'): ">1s"}
        color_map = {10: 2, 100: 3, 500: 4, 1000: 5, float('inf'): 6}
        
        for threshold in [10, 100, 500, 1000, float('inf')]:
            if y >= max_y - 2:
                break
            
            bucket = self.host_user_latency[host_user][threshold]
            counts = bucket.get_counts(current_time)
            
            val_10s = str(counts[10]) if show_windows[10] else "-"
            val_1m = str(counts[60]) if show_windows[60] else "-"
            val_10m = str(counts[600]) if show_windows[600] else "-"
            
            line = f"{latency_labels[threshold]:<10} {val_10s:<12} {val_1m:<12} {val_10m:<12}"
            
            try:
                stdscr.attron(curses.color_pair(color_map[threshold]))
                stdscr.addstr(y, x_offset, line[:col_width - 1])
                stdscr.attroff(curses.color_pair(color_map[threshold]))
            except:
                pass
            y += 1
        
        y += 1
        return y
    
    def draw_query_type_view(self, stdscr, height, width, y):
        current_time = time.time()
        
        if not self.query_type_latency:
            try:
                stdscr.addstr(y, 0, "No query data yet...")
            except:
                pass
            return
        
        sort_modes = ["Alphabetical", "QPS (High→Low)", "Slow Queries (High→Low)"]
        stdscr.attron(curses.A_BOLD)
        try:
            title = f"Latency Distribution by Query Type - [s]ort [Enter] view queries"
            stdscr.addstr(y, 0, title[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        start_y = y
        
        min_col_width = 48
        num_columns = max(1, width // min_col_width)
        col_width = width // num_columns
        
        query_types = list(self.query_type_latency.keys())
        
        if self.qtype_sort_mode == 0:
            query_types.sort()
        elif self.qtype_sort_mode == 1:
            type_query_counts = {}
            for qtype in query_types:
                total = 0
                for threshold in [10, 100, 500, 1000, float('inf')]:
                    bucket = self.query_type_latency[qtype][threshold]
                    counts = bucket.get_counts(current_time)
                    total += counts[10]
                type_query_counts[qtype] = total
            query_types.sort(key=lambda q: type_query_counts.get(q, 0), reverse=True)
        elif self.qtype_sort_mode == 2:
            type_slow_counts = {}
            for qtype in query_types:
                total = 0
                for threshold in [100, 500, 1000, float('inf')]:
                    bucket = self.query_type_latency[qtype][threshold]
                    counts = bucket.get_counts(current_time)
                    total += counts[10]
                type_slow_counts[qtype] = total
            query_types.sort(key=lambda q: type_slow_counts.get(q, 0), reverse=True)
        
        query_types_to_show = query_types[self.scroll_offset:]
        
        rows_per_type = 9
        max_rows = height - y - 2
        types_per_column = max_rows // rows_per_type
        
        for col_idx in range(num_columns):
            x_offset = col_idx * col_width
            start_idx = col_idx * types_per_column
            end_idx = start_idx + types_per_column
            column_types = query_types_to_show[start_idx:end_idx]
            
            y = start_y
            for qtype in column_types:
                if y >= height - 2:
                    break
                y = self._draw_query_type_table(stdscr, y, x_offset, col_width, qtype, current_time)
    
    def _draw_query_type_table(self, stdscr, y, x_offset, col_width, query_type, current_time):
        max_y = stdscr.getmaxyx()[0]
        
        if y >= max_y - 2:
            return y
        
        try:
            stdscr.attron(curses.A_BOLD)
            stdscr.addstr(y, x_offset, f"Type: {query_type}"[:col_width - 1])
            stdscr.attroff(curses.A_BOLD)
        except:
            pass
        y += 1
        
        if y >= max_y - 2:
            return y
        
        sparkline_width = min(25, col_width - 15)
        
        qps_history = self.qtype_qps_history.get(query_type, deque())
        if len(qps_history) >= 2:
            qps_spark = self._draw_sparkline(qps_history, sparkline_width, f'qtype_qps_{query_type}')
            qps_cur = qps_history[-1] if qps_history else 0
            try:
                stdscr.attron(curses.color_pair(3))
                line = f"QPS:{qps_spark} {qps_cur:.0f}/s"
                stdscr.addstr(y, x_offset, line[:col_width - 1])
                stdscr.attroff(curses.color_pair(3))
            except:
                pass
            y += 1
        
        if y >= max_y - 2:
            return y
        
        slow_history = self.qtype_slow_history.get(query_type, deque())
        if len(slow_history) >= 2:
            slow_spark = self._draw_sparkline(slow_history, sparkline_width, f'qtype_slow_{query_type}')
            slow_cur = slow_history[-1] if slow_history else 0
            try:
                stdscr.attron(curses.color_pair(6))
                line = f"Slw:{slow_spark} {slow_cur}"
                stdscr.addstr(y, x_offset, line[:col_width - 1])
                stdscr.attroff(curses.color_pair(6))
            except:
                pass
            y += 1
        
        if y >= max_y - 2:
            return y
        
        header = f"{'Latency':<10} {'10s':<12} {'1m':<12} {'10m':<12}"
        try:
            stdscr.attron(curses.A_BOLD)
            stdscr.addstr(y, x_offset, header[:col_width - 1])
            stdscr.attroff(curses.A_BOLD)
        except:
            pass
        y += 1
        
        show_windows = {
            10: self._should_show_time_window(10),
            60: self._should_show_time_window(60),
            600: self._should_show_time_window(600)
        }
        
        latency_labels = {10: "<10ms", 100: "<100ms", 500: "<500ms", 1000: "<1s", float('inf'): ">1s"}
        color_map = {10: 2, 100: 3, 500: 4, 1000: 5, float('inf'): 6}
        
        for threshold in [10, 100, 500, 1000, float('inf')]:
            if y >= max_y - 2:
                break
            
            bucket = self.query_type_latency[query_type][threshold]
            counts = bucket.get_counts(current_time)
            
            val_10s = str(counts[10]) if show_windows[10] else "-"
            val_1m = str(counts[60]) if show_windows[60] else "-"
            val_10m = str(counts[600]) if show_windows[600] else "-"
            
            line = f"{latency_labels[threshold]:<10} {val_10s:<12} {val_1m:<12} {val_10m:<12}"
            
            try:
                stdscr.attron(curses.color_pair(color_map[threshold]))
                stdscr.addstr(y, x_offset, line[:col_width - 1])
                stdscr.attroff(curses.color_pair(color_map[threshold]))
            except:
                pass
            y += 1
        
        y += 1
        return y
    
    def draw_recent_view(self, stdscr, height, width, y):
        if y >= height - 3:
            return
        
        recent = list(self.recent_critical)
        
        count_100 = sum(1 for q in recent if q.query_time * 1000 > 100)
        count_500 = sum(1 for q in recent if q.query_time * 1000 > 500)
        count_1000 = sum(1 for q in recent if q.query_time * 1000 > 1000)
        
        stdscr.attron(curses.A_BOLD)
        try:
            title = f"Slow Queries - Total: {len(recent)} (>100ms: {count_100}, >500ms: {count_500}, >1s: {count_1000}) - [Enter] for details"
            stdscr.addstr(y, 0, title[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        if y >= height - 3:
            return
        
        header = f"{'Time':<10} {'Age':<10} {'Host':<20} {'QTime':<10} Query"
        stdscr.attron(curses.A_BOLD)
        try:
            stdscr.addstr(y, 0, header[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        recent.reverse()
        
        visible_start = self.scroll_offset
        visible_end = min(len(recent), visible_start + (height - y - 2))
        
        for idx, query in enumerate(recent[visible_start:visible_end], start=visible_start):
            if y >= height - 3:
                break
            
            time_str = query.timestamp[-8:] if len(query.timestamp) >= 8 else query.timestamp
            age_str = self._format_time_ago(query.arrival_time)
            query_time_ms = query.query_time * 1000
            query_str = query.query[:max(1, width - 60)]
            
            line = f"{time_str:<10} {age_str:<10} {query.host:<20} {query_time_ms:<10.1f} {query_str}"
            
            try:
                query_time_in_ms = query.query_time * 1000
                if query_time_in_ms < 10:
                    color = 2
                elif query_time_in_ms < 100:
                    color = 3
                elif query_time_in_ms < 500:
                    color = 4
                elif query_time_in_ms < 1000:
                    color = 5
                else:
                    color = 6
                
                if idx == self.selected_index:
                    stdscr.attron(curses.color_pair(color) | curses.A_REVERSE)
                else:
                    stdscr.attron(curses.color_pair(color))
                
                stdscr.addstr(y, 0, line[:width - 1])
                
                if idx == self.selected_index:
                    stdscr.attroff(curses.color_pair(color) | curses.A_REVERSE)
                else:
                    stdscr.attroff(curses.color_pair(color))
            except:
                pass
            y += 1
        
        if not recent and y < height - 3:
            try:
                stdscr.addstr(y, 0, "No slow queries (>100ms) tracked yet")
            except:
                pass
    
    def draw_pattern_view(self, stdscr, height, width, y):
        if y >= height - 3:
            return
        
        sort_modes = ["Impact (Count×Avg)", "Count", "Avg Time", "Total Time"]
        
        filter_text = f" [Filter: {self.pattern_filter_host}]" if self.pattern_filter_active else ""
        
        stdscr.attron(curses.A_BOLD)
        try:
            title = f"Query Patterns (Sort: {sort_modes[self.pattern_sort_mode]}){filter_text} - [s]ort [f]ilter [Enter] queries"
            stdscr.addstr(y, 0, title[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        if y >= height - 3:
            return
        
        patterns = list(self.query_patterns.values())
        
        if self.pattern_filter_active and self.pattern_filter_host:
            patterns = [p for p in patterns if self.pattern_filter_host in p.hosts]
        
        total_queries = sum(p.count for p in self.query_patterns.values())
        
        header = f"{'#':<4} {'Count':<8} {'%':<6} {'AvgTime':<10} {'TotalTime':<12} {'Eff%':<7} {'Hosts':<6} Pattern"
        stdscr.attron(curses.A_BOLD)
        try:
            stdscr.addstr(y, 0, header[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        if not patterns:
            if y < height - 3:
                try:
                    if self.pattern_filter_active:
                        stdscr.addstr(y, 0, f"No patterns match filter: {self.pattern_filter_host}")
                    else:
                        stdscr.addstr(y, 0, "No query patterns tracked yet...")
                except:
                    pass
            return
        
        if self.pattern_sort_mode == 0:
            patterns.sort(key=lambda p: p.impact_score, reverse=True)
        elif self.pattern_sort_mode == 1:
            patterns.sort(key=lambda p: p.count, reverse=True)
        elif self.pattern_sort_mode == 2:
            patterns.sort(key=lambda p: p.avg_time, reverse=True)
        elif self.pattern_sort_mode == 3:
            patterns.sort(key=lambda p: p.total_time, reverse=True)
        
        visible_start = self.scroll_offset
        visible_end = min(len(patterns), visible_start + (height - y - 2))
        
        for idx, pattern in enumerate(patterns[visible_start:visible_end], start=visible_start):
            if y >= height - 3:
                break
            
            avg_time_ms = pattern.avg_time * 1000
            total_time_s = pattern.total_time
            efficiency = pattern.efficiency
            num_hosts = len(pattern.hosts)
            
            if total_queries > 0:
                percentage = (pattern.count / total_queries) * 100
            else:
                percentage = 0
            
            pattern_str = pattern.fingerprint[:max(1, width - 65)]
            
            line = f"{idx+1:<4} {pattern.count:<8} {percentage:<6.1f} {avg_time_ms:<10.1f} {total_time_s:<12.1f} {efficiency:<7.1f} {num_hosts:<6} {pattern_str}"
            
            try:
                if avg_time_ms < 100:
                    color = 3
                elif avg_time_ms < 500:
                    color = 4
                elif avg_time_ms < 1000:
                    color = 5
                else:
                    color = 6
                
                if idx == self.selected_index:
                    stdscr.attron(curses.color_pair(color) | curses.A_REVERSE)
                else:
                    stdscr.attron(curses.color_pair(color))
                
                stdscr.addstr(y, 0, line[:width - 1])
                
                if idx == self.selected_index:
                    stdscr.attroff(curses.color_pair(color) | curses.A_REVERSE)
                else:
                    stdscr.attroff(curses.color_pair(color))
            except:
                pass
            y += 1
    
    def draw_database_view(self, stdscr, height, width, y):
        if y >= height - 1:
            return
        
        sort_modes = ["Alphabetical", "Count", "Avg Time", "Total Time", "Lock Time"]
        
        stdscr.attron(curses.A_BOLD)
        try:
            title = f"Database/Table Breakdown - [s]ort [Tab] DB↔Table [↑↓] scroll [Enter] queries"
            stdscr.addstr(y, 0, title[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        if y >= height - 1:
            return
        
        # Toggle between database and table view with scroll_offset
        # Use negative scroll_offset to indicate table view
        showing_tables = hasattr(self, '_db_view_showing_tables') and self._db_view_showing_tables
        
        if showing_tables:
            # Show table stats
            tables = [(k, v) for k, v in self.table_stats.items()]
            
            if not tables:
                try:
                    stdscr.addstr(y, 0, "No table data yet...")
                except:
                    pass
                return
            
            # Sort tables
            if self.table_sort_mode == 0:
                tables.sort(key=lambda x: x[0])
            elif self.table_sort_mode == 1:
                tables.sort(key=lambda x: x[1]['count'], reverse=True)
            elif self.table_sort_mode == 2:
                tables.sort(key=lambda x: x[1]['total_time'] / max(x[1]['count'], 1), reverse=True)
            elif self.table_sort_mode == 3:
                tables.sort(key=lambda x: x[1]['total_time'], reverse=True)
            elif self.table_sort_mode == 4:
                tables.sort(key=lambda x: x[1]['total_lock_time'], reverse=True)
            
            header = f"{'Table':<30} {'DB':<15} {'Count':<8} {'AvgTime':<10} {'TotalTime':<12} {'LockTime':<10}"
            stdscr.attron(curses.A_BOLD)
            try:
                stdscr.addstr(y, 0, header[:width - 1])
            except:
                pass
            stdscr.attroff(curses.A_BOLD)
            y += 1
            
            visible_start = max(0, self.scroll_offset)
            visible_end = min(len(tables), visible_start + (height - y - 1))
            
            for idx, (table_key, stats) in enumerate(tables[visible_start:visible_end], start=visible_start):
                if y >= height - 1:
                    break
                
                # Extract table name from key
                table_name = table_key.split('.')[-1] if '.' in table_key else table_key
                db_name = stats['database'] if stats['database'] else 'N/A'
                count = stats['count']
                avg_time = (stats['total_time'] / count * 1000) if count > 0 else 0
                total_time = stats['total_time']
                lock_time = stats['total_lock_time']
                
                line = f"{table_name[:30]:<30} {db_name[:15]:<15} {count:<8} {avg_time:<10.1f} {total_time:<12.2f} {lock_time:<10.2f}"
                
                try:
                    if avg_time < 100:
                        color = 3
                    elif avg_time < 500:
                        color = 4
                    elif avg_time < 1000:
                        color = 5
                    else:
                        color = 6
                    
                    if idx == self.selected_index:
                        stdscr.attron(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        stdscr.attron(curses.color_pair(color))
                    
                    stdscr.addstr(y, 0, line[:width - 1])
                    
                    if idx == self.selected_index:
                        stdscr.attroff(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        stdscr.attroff(curses.color_pair(color))
                except:
                    pass
                y += 1
        else:
            # Show database stats
            databases = [(k, v) for k, v in self.database_stats.items()]
            
            if not databases:
                try:
                    stdscr.addstr(y, 0, "No database data yet...")
                except:
                    pass
                return
            
            # Sort databases
            if self.db_sort_mode == 0:
                databases.sort(key=lambda x: x[0])
            elif self.db_sort_mode == 1:
                databases.sort(key=lambda x: x[1]['count'], reverse=True)
            elif self.db_sort_mode == 2:
                databases.sort(key=lambda x: x[1]['total_time'] / max(x[1]['count'], 1), reverse=True)
            elif self.db_sort_mode == 3:
                databases.sort(key=lambda x: x[1]['total_time'], reverse=True)
            elif self.db_sort_mode == 4:
                databases.sort(key=lambda x: x[1]['total_lock_time'], reverse=True)
            
            header = f"{'Database':<25} {'Count':<10} {'AvgTime':<12} {'TotalTime':<14} {'LockTime':<12} {'AvgRows':<10}"
            stdscr.attron(curses.A_BOLD)
            try:
                stdscr.addstr(y, 0, header[:width - 1])
            except:
                pass
            stdscr.attroff(curses.A_BOLD)
            y += 1
            
            visible_start = max(0, self.scroll_offset)
            visible_end = min(len(databases), visible_start + (height - y - 1))
            
            for idx, (db_name, stats) in enumerate(databases[visible_start:visible_end], start=visible_start):
                if y >= height - 1:
                    break
                
                count = stats['count']
                avg_time = (stats['total_time'] / count * 1000) if count > 0 else 0
                total_time = stats['total_time']
                lock_time = stats['total_lock_time']
                avg_rows = stats['total_rows_examined'] / count if count > 0 else 0
                
                line = f"{db_name[:25]:<25} {count:<10} {avg_time:<12.1f} {total_time:<14.2f} {lock_time:<12.2f} {avg_rows:<10.0f}"
                
                try:
                    if avg_time < 100:
                        color = 3
                    elif avg_time < 500:
                        color = 4
                    elif avg_time < 1000:
                        color = 5
                    else:
                        color = 6
                    
                    if idx == self.selected_index:
                        stdscr.attron(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        stdscr.attron(curses.color_pair(color))
                    
                    stdscr.addstr(y, 0, line[:width - 1])
                    
                    if idx == self.selected_index:
                        stdscr.attroff(curses.color_pair(color) | curses.A_REVERSE)
                    else:
                        stdscr.attroff(curses.color_pair(color))
                except:
                    pass
                y += 1
    
    def draw_lock_view(self, stdscr, height, width, y):
        if y >= height - 1:
            return
        
        sort_modes = ["Recent First", "Lock Time (High→Low)", "Query Time (High→Low)"]
        
        stdscr.attron(curses.A_BOLD)
        try:
            title = f"Lock Contention Analysis - [s]ort [↑↓] scroll [Enter] details"
            stdscr.addstr(y, 0, title[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        if y >= height - 1:
            return
        
        queries = list(self.high_lock_queries)
        
        if not queries:
            try:
                stdscr.addstr(y, 0, "No high lock time queries (>100ms) tracked yet")
            except:
                pass
            return
        
        # Sort queries
        if self.lock_sort_mode == 0:
            queries.reverse()  # Most recent first
        elif self.lock_sort_mode == 1:
            queries.sort(key=lambda q: q.lock_time, reverse=True)
        elif self.lock_sort_mode == 2:
            queries.sort(key=lambda q: q.query_time, reverse=True)
        
        total_lock_time = sum(q.lock_time for q in queries)
        avg_lock_time = total_lock_time / len(queries) if queries else 0
        
        info_line = f"Total High-Lock Queries: {len(queries)} | Avg Lock: {avg_lock_time*1000:.1f}ms | Total Lock Time: {total_lock_time:.2f}s"
        try:
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(y, 0, info_line[:width - 1])
            stdscr.attroff(curses.color_pair(4))
        except:
            pass
        y += 1
        
        if y >= height - 1:
            return
        
        header = f"{'Time':<10} {'Age':<10} {'Host':<20} {'LockTime':<10} {'QTime':<10} Query"
        stdscr.attron(curses.A_BOLD)
        try:
            stdscr.addstr(y, 0, header[:width - 1])
        except:
            pass
        stdscr.attroff(curses.A_BOLD)
        y += 1
        
        visible_start = self.scroll_offset
        visible_end = min(len(queries), visible_start + (height - y - 1))
        
        for idx, query in enumerate(queries[visible_start:visible_end], start=visible_start):
            if y >= height - 1:
                break
            
            time_str = query.timestamp[-8:] if len(query.timestamp) >= 8 else query.timestamp
            age_str = self._format_time_ago(query.arrival_time)
            lock_time_ms = query.lock_time * 1000
            query_time_ms = query.query_time * 1000
            query_str = query.query[:max(1, width - 70)]
            
            line = f"{time_str:<10} {age_str:<10} {query.host:<20} {lock_time_ms:<10.1f} {query_time_ms:<10.1f} {query_str}"
            
            try:
                # Color based on lock time
                if lock_time_ms < 500:
                    color = 4  # Yellow
                elif lock_time_ms < 1000:
                    color = 5  # Magenta
                else:
                    color = 6  # Red
                
                if idx == self.selected_index:
                    stdscr.attron(curses.color_pair(color) | curses.A_REVERSE)
                else:
                    stdscr.attron(curses.color_pair(color))
                
                stdscr.addstr(y, 0, line[:width - 1])
                
                if idx == self.selected_index:
                    stdscr.attroff(curses.color_pair(color) | curses.A_REVERSE)
                else:
                    stdscr.attroff(curses.color_pair(color))
            except:
                pass
            y += 1
    
    def run(self, stdscr):
        def signal_handler(sig, frame):
            self.should_exit = True
        
        signal.signal(signal.SIGINT, signal_handler)
        
        curses.curs_set(0)
        stdscr.nodelay(1)
        
        if self.low_cpu:
            stdscr.timeout(500)
        else:
            stdscr.timeout(100)
        
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(6, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)
        
        self.start_time = time.time()
        last_update = 0
        last_draw = 0
        
        if not self.from_start:
            pass
        else:
            self.parse_slow_log()
        
        while True:
            current_time = time.time()
            
            if self.should_exit:
                break
            
            if not self.paused and current_time - last_update >= self.refresh_rate:
                new_queries = self.parse_slow_log()
                last_update = current_time
                self.last_update_time = current_time
                if new_queries > 0:
                    self.data_changed = True
            
            time_until_refresh = self.refresh_rate - (current_time - last_update)
            
            redraw_interval = 2.0 if self.low_cpu else 1.0
            
            if self.data_changed or (current_time - last_draw >= redraw_interval):
                stdscr.clear()
                height, width = stdscr.getmaxyx()
                
                self.draw_header(stdscr, height, width, time_until_refresh)
                y = 2
                
                if self.view_mode == 0:
                    self.draw_global_view(stdscr, height, width, y)
                elif self.view_mode == 1:
                    self.draw_host_view(stdscr, height, width, y)
                elif self.view_mode == 2:
                    self.draw_query_type_view(stdscr, height, width, y)
                elif self.view_mode == 3:
                    self.draw_recent_view(stdscr, height, width, y)
                elif self.view_mode == 4:
                    self.draw_pattern_view(stdscr, height, width, y)
                elif self.view_mode == 5:
                    self.draw_database_view(stdscr, height, width, y)
                elif self.view_mode == 6:
                    self.draw_lock_view(stdscr, height, width, y)
                
                # Footer with all status info
                mem_mb = self._get_memory_usage()
                
                if self.last_update_time:
                    last_update_str = datetime.fromtimestamp(self.last_update_time).strftime('%H:%M:%S')
                else:
                    last_update_str = "Never"
                
                if self.start_time:
                    time_started = datetime.fromtimestamp(self.start_time).strftime('%H:%M:%S')
                else:
                    time_started = "N/A"
                
                # Get system health
                health_status, health_color = self._get_system_health()
                recent = list(self.recent_critical)
                slow_1m = sum(1 for q in recent if time.time() - q.arrival_time < 60 and q.query_time * 1000 > 1000)
                
                # Use ASCII icons
                if health_status == "CRITICAL":
                    health_icon = "[XX]"
                elif health_status == "WARNING":
                    health_icon = "[!!]"
                else:
                    health_icon = "[OK]"
                
                # Build footer with colored/bold components
                if height > 1:
                    try:
                        stdscr.attron(curses.color_pair(1))
                        x = 0
                        
                        # Filename
                        part = f" {self.log_path.name} | "
                        stdscr.addstr(height - 1, x, part)
                        x += len(part)
                        
                        # Health status (colored and bold)
                        stdscr.attroff(curses.color_pair(1))
                        stdscr.attron(curses.color_pair(health_color) | curses.A_BOLD)
                        stdscr.addstr(height - 1, x, health_icon)
                        x += len(health_icon)
                        stdscr.attroff(curses.color_pair(health_color) | curses.A_BOLD)
                        stdscr.attron(curses.color_pair(1))
                        
                        # Slow queries
                        part = " | SLW:"
                        stdscr.addstr(height - 1, x, part)
                        x += len(part)
                        
                        # Slow count (bold, colored if high)
                        slow_str = str(slow_1m)
                        if slow_1m > 50:
                            stdscr.attroff(curses.color_pair(1))
                            stdscr.attron(curses.color_pair(6) | curses.A_BOLD)  # Red
                        elif slow_1m > 20:
                            stdscr.attroff(curses.color_pair(1))
                            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)  # Yellow
                        else:
                            stdscr.attron(curses.A_BOLD)
                        stdscr.addstr(height - 1, x, slow_str)
                        x += len(slow_str)
                        if slow_1m > 20:
                            stdscr.attroff(curses.color_pair(6) if slow_1m > 50 else curses.color_pair(4))
                            stdscr.attroff(curses.A_BOLD)
                            stdscr.attron(curses.color_pair(1))
                        else:
                            stdscr.attroff(curses.A_BOLD)
                        
                        # Parse errors
                        part = " | ERR:"
                        stdscr.addstr(height - 1, x, part)
                        x += len(part)
                        
                        # Error count (bold, colored if > 0)
                        err_str = str(self.parse_errors)
                        if self.parse_errors > 0:
                            stdscr.attroff(curses.color_pair(1))
                            stdscr.attron(curses.color_pair(6) | curses.A_BOLD)  # Red
                        else:
                            stdscr.attron(curses.A_BOLD)
                        stdscr.addstr(height - 1, x, err_str)
                        x += len(err_str)
                        if self.parse_errors > 0:
                            stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
                            stdscr.attron(curses.color_pair(1))
                        else:
                            stdscr.attroff(curses.A_BOLD)
                        
                        # Memory
                        part = " | MEM:"
                        stdscr.addstr(height - 1, x, part)
                        x += len(part)
                        
                        # Memory value (bold)
                        stdscr.attron(curses.A_BOLD)
                        mem_str = f"{mem_mb:.0f}MB"
                        stdscr.addstr(height - 1, x, mem_str)
                        x += len(mem_str)
                        stdscr.attroff(curses.A_BOLD)
                        
                        # Updated time
                        part = " | UPD:"
                        stdscr.addstr(height - 1, x, part)
                        x += len(part)
                        
                        # Updated time value (bold)
                        stdscr.attron(curses.A_BOLD)
                        stdscr.addstr(height - 1, x, last_update_str)
                        x += len(last_update_str)
                        stdscr.attroff(curses.A_BOLD)
                        
                        # Started time
                        part = " | START:"
                        stdscr.addstr(height - 1, x, part)
                        x += len(part)
                        
                        # Started time value (bold)
                        stdscr.attron(curses.A_BOLD)
                        stdscr.addstr(height - 1, x, time_started)
                        x += len(time_started)
                        stdscr.attroff(curses.A_BOLD)
                        
                        # Pad rest of line
                        remaining = " " * (width - x - 1)
                        if len(remaining) > 0:
                            stdscr.addstr(height - 1, x, remaining)
                        
                        stdscr.attroff(curses.color_pair(1))
                    except:
                        pass
                
                stdscr.refresh()
                last_draw = current_time
                self.data_changed = False
            
            try:
                key = stdscr.getch()
                if key == -1:
                    if self.paused and self.low_cpu:
                        time.sleep(0.5)
                    continue
                    
                if key == ord('q'):
                    break
                elif key == ord('?'):
                    self.show_help_popup(stdscr)
                    self.data_changed = True
                elif key == ord('d'):
                    self.show_detailed_stats_popup(stdscr)
                    self.data_changed = True
                elif key == ord('e'):
                    self.export_current_view(stdscr)
                    self.data_changed = True
                elif key == ord('/'):
                    search_term = self.show_search_dialog(stdscr)
                    if search_term:
                        self.search_query = search_term
                        self.search_mode = True
                    self.data_changed = True
                elif key == ord('p'):
                    self.paused = not self.paused
                    self.data_changed = True
                elif key == ord('c'):
                    if self.view_mode == 4:
                        self.pattern_filter_host = ""
                        self.pattern_filter_active = False
                        self.data_changed = True
                    else:
                        self.latency_buckets = {k: LatencyBucket() for k in self.latency_buckets}
                        self.host_latency.clear()
                        self.host_user_latency.clear()
                        self.query_type_latency.clear()
                        self.recent_critical.clear()
                        self.query_patterns.clear()
                        self.database_stats.clear()
                        self.table_stats.clear()
                        self.high_lock_queries.clear()
                        self.qps_history.clear()
                        self.slow_query_history.clear()
                        self.host_qps_history.clear()
                        self.host_slow_history.clear()
                        self.qtype_qps_history.clear()
                        self.qtype_slow_history.clear()
                        self.total_queries = 0
                        self.parse_errors = 0
                        self.start_time = time.time()
                        self.scroll_offset = 0
                        self.selected_index = 0
                        self.data_changed = True
                elif key == ord('f'):
                    if self.view_mode == 4:
                        self.show_pattern_filter_dialog(stdscr)
                        self.scroll_offset = 0
                elif key == ord('1'):
                    self.view_mode = 0
                    self.scroll_offset = 0
                    self.selected_index = 0
                    self.data_changed = True
                elif key == ord('2'):
                    self.view_mode = 1
                    self.scroll_offset = 0
                    self.selected_index = 0
                    self.data_changed = True
                elif key == ord('3'):
                    self.view_mode = 2
                    self.scroll_offset = 0
                    self.selected_index = 0
                    self.data_changed = True
                elif key == ord('4'):
                    self.view_mode = 3
                    self.scroll_offset = 0
                    self.selected_index = 0
                    self.data_changed = True
                elif key == ord('5'):
                    self.view_mode = 4
                    self.scroll_offset = 0
                    self.selected_index = 0
                    self.data_changed = True
                elif key == ord('6'):
                    self.view_mode = 5
                    self.scroll_offset = 0
                    self.selected_index = 0
                    if not hasattr(self, '_db_view_showing_tables'):
                        self._db_view_showing_tables = False
                    self.data_changed = True
                elif key == ord('7'):
                    self.view_mode = 6
                    self.scroll_offset = 0
                    self.selected_index = 0
                    self.data_changed = True
                elif key == 9:  # Tab key
                    if self.view_mode == 5:
                        # Toggle between database and table view
                        self._db_view_showing_tables = not getattr(self, '_db_view_showing_tables', False)
                        self.scroll_offset = 0
                        self.selected_index = 0
                        self.data_changed = True
                elif key == ord('s'):
                    if self.view_mode == 1:
                        self.host_sort_mode = (self.host_sort_mode + 1) % 3
                        self.data_changed = True
                    elif self.view_mode == 2:
                        self.qtype_sort_mode = (self.qtype_sort_mode + 1) % 3
                        self.data_changed = True
                    elif self.view_mode == 4:
                        self.pattern_sort_mode = (self.pattern_sort_mode + 1) % 4
                        self.data_changed = True
                    elif self.view_mode == 5:
                        if getattr(self, '_db_view_showing_tables', False):
                            self.table_sort_mode = (self.table_sort_mode + 1) % 5
                        else:
                            self.db_sort_mode = (self.db_sort_mode + 1) % 5
                        self.data_changed = True
                    elif self.view_mode == 6:
                        self.lock_sort_mode = (self.lock_sort_mode + 1) % 3
                        self.data_changed = True
                elif key == curses.KEY_UP:
                    if self.view_mode == 3:
                        # RECENT CRITICAL view
                        self.selected_index = max(0, self.selected_index - 1)
                        if self.selected_index < self.scroll_offset:
                            self.scroll_offset = self.selected_index
                    elif self.view_mode == 4:
                        # QUERY PATTERNS view
                        self.selected_index = max(0, self.selected_index - 1)
                        if self.selected_index < self.scroll_offset:
                            self.scroll_offset = self.selected_index
                    elif self.view_mode == 5:
                        # DATABASE/TABLE view
                        self.selected_index = max(0, self.selected_index - 1)
                        if self.selected_index < self.scroll_offset:
                            self.scroll_offset = self.selected_index
                    elif self.view_mode == 6:
                        # LOCK CONTENTION view
                        self.selected_index = max(0, self.selected_index - 1)
                        if self.selected_index < self.scroll_offset:
                            self.scroll_offset = self.selected_index
                    else:
                        self.scroll_offset = max(0, self.scroll_offset - 1)
                    self.data_changed = True
                elif key == curses.KEY_DOWN:
                    if self.view_mode == 3:
                        # RECENT CRITICAL view
                        recent_count = len(self.recent_critical)
                        if recent_count > 0:
                            self.selected_index = min(recent_count - 1, self.selected_index + 1)
                            height, _ = stdscr.getmaxyx()
                            visible_lines = height - 6
                            if self.selected_index >= self.scroll_offset + visible_lines:
                                self.scroll_offset = self.selected_index - visible_lines + 1
                    elif self.view_mode == 4:
                        # QUERY PATTERNS view
                        patterns = list(self.query_patterns.values())
                        if self.pattern_filter_active and self.pattern_filter_host:
                            patterns = [p for p in patterns if self.pattern_filter_host in p.hosts]
                        
                        pattern_count = len(patterns)
                        if pattern_count > 0:
                            self.selected_index = min(pattern_count - 1, self.selected_index + 1)
                            height, _ = stdscr.getmaxyx()
                            visible_lines = height - 6
                            if self.selected_index >= self.scroll_offset + visible_lines:
                                self.scroll_offset = self.selected_index - visible_lines + 1
                    elif self.view_mode == 5:
                        # DATABASE/TABLE view
                        if getattr(self, '_db_view_showing_tables', False):
                            item_count = len(self.table_stats)
                        else:
                            item_count = len(self.database_stats)
                        
                        if item_count > 0:
                            self.selected_index = min(item_count - 1, self.selected_index + 1)
                            height, _ = stdscr.getmaxyx()
                            visible_lines = height - 6
                            if self.selected_index >= self.scroll_offset + visible_lines:
                                self.scroll_offset = self.selected_index - visible_lines + 1
                    elif self.view_mode == 6:
                        # LOCK CONTENTION view
                        lock_count = len(self.high_lock_queries)
                        if lock_count > 0:
                            self.selected_index = min(lock_count - 1, self.selected_index + 1)
                            height, _ = stdscr.getmaxyx()
                            visible_lines = height - 6
                            if self.selected_index >= self.scroll_offset + visible_lines:
                                self.scroll_offset = self.selected_index - visible_lines + 1
                    else:
                        self.scroll_offset += 1
                    self.data_changed = True
                elif key == 10 or key == curses.KEY_ENTER:
                    if self.view_mode == 1 and len(self.host_user_latency) > 0:
                        # BY HOST view - show host selector then queries
                        self.show_host_selector_dialog(stdscr)
                        self.data_changed = True
                    
                    elif self.view_mode == 2 and len(self.query_type_latency) > 0:
                        # BY QUERY TYPE view - show type selector then queries
                        self.show_query_type_selector_dialog(stdscr)
                        self.data_changed = True
                    
                    elif self.view_mode == 3 and len(self.recent_critical) > 0:
                        # RECENT CRITICAL view - show query details
                        recent = list(self.recent_critical)
                        recent.reverse()
                        if 0 <= self.selected_index < len(recent):
                            self.show_query_details_popup(stdscr, recent[self.selected_index])
                            self.data_changed = True
                    
                    elif self.view_mode == 4 and len(self.query_patterns) > 0:
                        # QUERY PATTERNS view - show queries matching selected pattern
                        patterns = list(self.query_patterns.values())
                        
                        # Apply filter if active
                        if self.pattern_filter_active and self.pattern_filter_host:
                            patterns = [p for p in patterns if self.pattern_filter_host in p.hosts]
                        
                        # Sort patterns same way as display
                        if self.pattern_sort_mode == 0:
                            patterns.sort(key=lambda p: p.impact_score, reverse=True)
                        elif self.pattern_sort_mode == 1:
                            patterns.sort(key=lambda p: p.count, reverse=True)
                        elif self.pattern_sort_mode == 2:
                            patterns.sort(key=lambda p: p.avg_time, reverse=True)
                        elif self.pattern_sort_mode == 3:
                            patterns.sort(key=lambda p: p.total_time, reverse=True)
                        
                        if 0 <= self.selected_index < len(patterns):
                            selected_pattern = patterns[self.selected_index]
                            self.show_pattern_queries_popup(stdscr, selected_pattern)
                            self.data_changed = True
                    
                    elif self.view_mode == 5:
                        # DATABASE/TABLE view - show queries for selected database or table
                        if getattr(self, '_db_view_showing_tables', False):
                            # Table view
                            tables = [(k, v) for k, v in self.table_stats.items()]
                            if self.table_sort_mode == 0:
                                tables.sort(key=lambda x: x[0])
                            elif self.table_sort_mode == 1:
                                tables.sort(key=lambda x: x[1]['count'], reverse=True)
                            elif self.table_sort_mode == 2:
                                tables.sort(key=lambda x: x[1]['total_time'] / max(x[1]['count'], 1), reverse=True)
                            elif self.table_sort_mode == 3:
                                tables.sort(key=lambda x: x[1]['total_time'], reverse=True)
                            elif self.table_sort_mode == 4:
                                tables.sort(key=lambda x: x[1]['total_lock_time'], reverse=True)
                            
                            if 0 <= self.selected_index < len(tables):
                                table_key, table_stats = tables[self.selected_index]
                                queries = list(table_stats['queries'])
                                if queries:
                                    self.show_generic_queries_popup(stdscr, f"Table: {table_key}", queries)
                                self.data_changed = True
                        else:
                            # Database view
                            databases = [(k, v) for k, v in self.database_stats.items()]
                            if self.db_sort_mode == 0:
                                databases.sort(key=lambda x: x[0])
                            elif self.db_sort_mode == 1:
                                databases.sort(key=lambda x: x[1]['count'], reverse=True)
                            elif self.db_sort_mode == 2:
                                databases.sort(key=lambda x: x[1]['total_time'] / max(x[1]['count'], 1), reverse=True)
                            elif self.db_sort_mode == 3:
                                databases.sort(key=lambda x: x[1]['total_time'], reverse=True)
                            elif self.db_sort_mode == 4:
                                databases.sort(key=lambda x: x[1]['total_lock_time'], reverse=True)
                            
                            if 0 <= self.selected_index < len(databases):
                                db_name, db_stats = databases[self.selected_index]
                                queries = list(db_stats['queries'])
                                if queries:
                                    self.show_generic_queries_popup(stdscr, f"Database: {db_name}", queries)
                                self.data_changed = True
                    
                    elif self.view_mode == 6 and len(self.high_lock_queries) > 0:
                        # LOCK CONTENTION view - show query details
                        queries = list(self.high_lock_queries)
                        
                        if self.lock_sort_mode == 0:
                            queries.reverse()
                        elif self.lock_sort_mode == 1:
                            queries.sort(key=lambda q: q.lock_time, reverse=True)
                        elif self.lock_sort_mode == 2:
                            queries.sort(key=lambda q: q.query_time, reverse=True)
                        
                        if 0 <= self.selected_index < len(queries):
                            self.show_query_details_popup(stdscr, queries[self.selected_index])
                            self.data_changed = True
            except:
                pass


def main():
    parser = argparse.ArgumentParser(
        description='MariaDB Slow Query Monitor with Pattern Analysis v2.0.0'
    )
    parser.add_argument('--log-path', default='/var/log/mysql/mariadb-slow.log', 
                       help='Path to slow query log')
    parser.add_argument('--refresh', type=float, default=10.0, 
                       help='Refresh rate in seconds (default: 10.0)')
    parser.add_argument('--max-queries', type=int, default=10000, 
                       help='Maximum queries to buffer (default: 10000)')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug output')
    parser.add_argument('--from-start', action='store_true', 
                       help='Read from start of log file (default: start from end)')
    parser.add_argument('--low-cpu', action='store_true',
                       help='Low CPU mode: reduces screen updates and polling')
    
    args = parser.parse_args()
    
    monitor = SlowLogMonitor(
        args.log_path, 
        args.refresh, 
        args.max_queries, 
        args.debug, 
        args.from_start,
        args.low_cpu
    )
    
    try:
        curses.wrapper(monitor.run)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
