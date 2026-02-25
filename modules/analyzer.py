import re
from datetime import datetime
from pathlib import Path
from typing import Dict

class CiscoAnalyzer:
    """Analyzes collected data and generates detailed reports"""
    
    def __init__(self, collected_data: Dict[str, str], command_info: Dict):
        self.data = collected_data
        self.command_info = command_info
        self.findings = {
            'critical': [],  # Critical issues
            'warning': [],   # Warnings
            'info': [],      # Informational items
        }
        self.detailed_results = {}  # Detailed analysis results by command
    
    def _init_result(self, command: str) -> dict:
        """Initialize result dictionary with command metadata"""
        command_info = self.command_info.get(command, {})
        return {
            'title': command_info.get('title', 'Unknown'),
            'description': command_info.get('report_desc', ''),
            'command': command,
            'items': []
        }
    
    def _get_section(self, command: str) -> str:
        """Get output of specific command"""
        return self.data.get(command, "")
    
    def analyze_all(self):
        """Analyze all data"""
        print("\n" + "=" * 80)
        print("📊 Starting Data Analysis")
        print("=" * 80 + "\n")
        
        # Execute each analysis function
        self.analyze_version()
        self.analyze_cpu()
        self.analyze_memory()
        self.analyze_environment()
        self.analyze_platform_resources()
        self.analyze_interfaces_errors()
        self.analyze_obfl_uptime()
        self.analyze_obfl_messages()
        self.analyze_obfl_temperature()
        self.analyze_obfl_voltage()
        self.analyze_reload()
        self.analyze_error_logs()
        self.analyze_routing()
        self.analyze_arp()
        self.analyze_mac_table()
        self.analyze_interfaces_status()
        self.analyze_interfaces_description()
        self.analyze_tcam()
        self.analyze_control_processor()
        self.analyze_inventory()
        self.analyze_redundancy()
        self.analyze_switch_stack()
        self.analyze_crashinfo()
        self.analyze_stacks()
        self.analyze_core_dump()
        self.analyze_cpu_history()
        self.analyze_cpu_queue()
        
        print("✅ Analysis complete\n")
    
    def analyze_version(self):
        """Analyze system version and uptime
        
        Description:
        - IOS Version: Cisco network operating system version (includes security patches, bug fixes)
        - Uptime: Time since last reboot
        - Reload Reason: Normal/Abnormal reboot classification
        """
        command = 'show version'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # IOS Version
        version_match = re.search(r'Version ([\d.]+)', section)
        if version_match:
            version = version_match.group(1)
            result['items'].append({
                'name': 'IOS Version',
                'value': version,
                'description': 'Cisco IOS XE operating system version',
                'status': 'warning' if float(version.split('.')[0]) < 17 else 'normal'
            })
            
            if float(version.split('.')[0]) < 17:
                self.findings['warning'].append({
                    'category': 'System',
                    'issue': f'Outdated IOS version ({version})',
                    'impact': 'May contain security vulnerabilities and known bugs',
                    'action': 'Check Cisco.com for latest recommended version and plan upgrade'
                })
        
        # Uptime
        uptime_match = re.search(r'uptime is (.+)', section)
        if uptime_match:
            uptime = uptime_match.group(1).strip()
            result['items'].append({
                'name': 'Uptime',
                'value': uptime,
                'description': 'Time since last reboot',
                'status': 'warning' if any(x in uptime for x in ['minute', 'hour']) and 'day' not in uptime else 'normal'
            })
            
            if 'minute' in uptime or ('hour' in uptime and 'day' not in uptime):
                self.findings['warning'].append({
                    'category': 'System',
                    'issue': f'Recent reboot detected (Uptime: {uptime})',
                    'impact': 'Possible service interruption or unstable state',
                    'action': 'Investigate reboot cause and analyze logs'
                })
        
        # Reload Reason
        reload_match = re.search(r'Last reload reason: (.+)', section)
        if reload_match:
            reload_reason = reload_match.group(1).strip()
            
            # Determine if abnormal reboot
            abnormal_reasons = ['PowerOn', 'Watchdog', 'crash', 'Exception', 'abort']
            is_abnormal = any(r in reload_reason for r in abnormal_reasons)
            
            result['items'].append({
                'name': 'Last Reload Reason',
                'value': reload_reason,
                'description': 'Reason for the last reboot',
                'status': 'critical' if is_abnormal else 'normal'
            })
            
            if is_abnormal:
                self.findings['critical'].append({
                    'category': 'System',
                    'issue': f'Abnormal reboot detected: {reload_reason}',
                    'impact': 'PowerOn indicates power issue, Watchdog/crash indicates SW/HW failure',
                    'action': 'Review OBFL logs and crashinfo, consider opening TAC case'
                })
        
        # Model
        model_match = re.search(r'Model [Nn]umber\s+:\s+(\S+)', section)
        if model_match:
            result['items'].append({
                'name': 'Model',
                'value': model_match.group(1),
                'description': 'Device hardware model',
                'status': 'normal'
            })
        
        self.detailed_results['version'] = result
    
    def analyze_cpu(self):
        """Analyze CPU usage
        
        Description:
        - CPU Usage: Control plane processing load
        - 5sec/1min/5min: Average usage over each period
        - High CPU: May be caused by routing updates, traffic processing, attacks
        """
        command = 'show processes cpu sorted'
        section = self._get_section(command)
        result = self._init_result(command)
        
        cpu_match = re.search(r'CPU utilization.+five seconds: (\d+)%.*one minute: (\d+)%.*five minutes: (\d+)%', section)
        if cpu_match:
            cpu_5s, cpu_1m, cpu_5m = map(int, cpu_match.groups())
            
            status = 'normal'
            if cpu_5m > 80:
                status = 'critical'
            elif cpu_5m > 50:
                status = 'warning'
            
            result['items'].append({
                'name': 'CPU Usage (5min avg)',
                'value': f'{cpu_5m}%',
                'description': 'Average CPU usage over last 5 minutes (Normal if below 30% for network devices)',
                'status': status,
                'details': f'5sec: {cpu_5s}%, 1min: {cpu_1m}%, 5min: {cpu_5m}%'
            })
            
            if cpu_5m > 80:
                self.findings['critical'].append({
                    'category': 'CPU',
                    'issue': f'CPU overload (5min avg: {cpu_5m}%)',
                    'impact': 'May cause packet drops, routing instability, management access delays',
                    'action': 'Check top CPU processes, disable unnecessary features, analyze traffic patterns'
                })
            elif cpu_5m > 50:
                self.findings['warning'].append({
                    'category': 'CPU',
                    'issue': f'High CPU usage (5min avg: {cpu_5m}%)',
                    'impact': 'Performance degradation possible under increased load',
                    'action': 'Continuous monitoring required'
                })
        
        # Top CPU processes
        top_processes = []
        lines = section.split('\n')
        for line in lines[3:8]:  # Top 5 processes
            if '%' in line and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        cpu_pct = parts[0].strip('%')
                        if cpu_pct.replace('.', '').isdigit():
                            process_name = parts[-1] if len(parts) > 1 else 'Unknown'
                            top_processes.append(f'{process_name}: {cpu_pct}%')
                    except:
                        pass
        
        if top_processes:
            result['items'].append({
                'name': 'Top CPU Processes',
                'value': ', '.join(top_processes[:3]),
                'description': 'Processes consuming the most CPU',
                'status': 'normal'
            })
        
        self.detailed_results['cpu'] = result
    
    def analyze_memory(self):
        """Analyze memory usage
        
        Description:
        - Memory: Available system RAM
        - Usage: Consumed by routing tables, MAC tables, processes, etc.
        - >90%: System instability possible due to memory shortage
        """
        command = 'show processes memory sorted'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Processor Pool
        mem_match = re.search(r'Processor Pool Total:\s+(\d+)\s+Used:\s+(\d+)\s+Free:\s+(\d+)', section)
        if mem_match:
            total, used, free = map(int, mem_match.groups())
            used_pct = (used / total * 100) if total > 0 else 0
            
            status = 'normal'
            if used_pct > 90:
                status = 'critical'
            elif used_pct > 80:
                status = 'warning'
            
            result['items'].append({
                'name': 'Memory Usage',
                'value': f'{used_pct:.1f}%',
                'description': f'{used//1024//1024}MB used out of {total//1024//1024}MB total',
                'status': status,
                'details': f'Total: {total//1024//1024}MB, Used: {used//1024//1024}MB, Free: {free//1024//1024}MB'
            })
            
            if used_pct > 90:
                self.findings['critical'].append({
                    'category': 'Memory',
                    'issue': f'Memory shortage ({used_pct:.1f}% used)',
                    'impact': 'May cause system instability, process crashes, feature limitations',
                    'action': 'Check for memory leaks, disable unnecessary features, consider hardware upgrade'
                })
            elif used_pct > 80:
                self.findings['warning'].append({
                    'category': 'Memory',
                    'issue': f'High memory usage ({used_pct:.1f}%)',
                    'impact': 'Risk of memory exhaustion when enabling additional features',
                    'action': 'Monitor memory usage trends'
                })
        
        self.detailed_results['memory'] = result
    
    def analyze_environment(self):
        """Analyze environmental sensors
        
        Description:
        - Temperature: Device overheating status (Inlet: external air, Hotspot: internal max temp)
        - Fan: Cooling system operational status
        - Power: Power supply status (redundancy recommended)
        """
        command = 'show environment all'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Temperature
        for line in section.split('\n'):
            if 'Temperature' in line and '°C' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if '°C' in part:
                        try:
                            temp = int(part.replace('°C', ''))
                            sensor_name = ' '.join(parts[:i])
                            
                            status = 'normal'
                            threshold = ''
                            
                            if 'Inlet' in sensor_name:
                                if temp > 46:
                                    status = 'critical'
                                    threshold = ' (Normal: 0-46°C)'
                                elif temp > 40:
                                    status = 'warning'
                                    threshold = ' (Caution: above 40°C)'
                                else:
                                    threshold = ' (Normal range)'
                            elif 'Hotspot' in sensor_name:
                                if temp > 105:
                                    status = 'critical'
                                    threshold = ' (Normal: 0-105°C)'
                                elif temp > 90:
                                    status = 'warning'
                                    threshold = ' (Caution: above 90°C)'
                                else:
                                    threshold = ' (Normal range)'
                            
                            result['items'].append({
                                'name': sensor_name,
                                'value': f'{temp}°C',
                                'description': f'Sensor temperature{threshold}',
                                'status': status
                            })
                            
                            if status == 'critical':
                                self.findings['critical'].append({
                                    'category': 'Environment',
                                    'issue': f'{sensor_name} overheating ({temp}°C)',
                                    'impact': 'May cause hardware damage and automatic shutdown',
                                    'action': 'Improve cooling immediately, remove dust, check air conditioning'
                                })
                        except:
                            pass
        
        # Fan status
        fan_lines = [line for line in section.split('\n') if 'FAN' in line.upper() and 'Speed' in line]
        for line in fan_lines:
            if 'OK' in line or 'Normal' in line:
                result['items'].append({
                    'name': 'Fan Status',
                    'value': 'OK',
                    'description': 'Cooling fan operating normally',
                    'status': 'normal'
                })
            else:
                result['items'].append({
                    'name': 'Fan Status',
                    'value': 'ERROR',
                    'description': 'Fan problem detected',
                    'status': 'critical'
                })
                self.findings['critical'].append({
                    'category': 'Environment',
                    'issue': 'Fan error detected',
                    'impact': 'Risk of overheating and equipment shutdown due to poor cooling',
                    'action': 'Replace fan, request TAC support'
                })
        
        # Power supply
        ps_lines = [line for line in section.split('\n') if line.strip().startswith('PS') and 'Supply' in line]
        ps_count = len([l for l in ps_lines if 'OK' in l or 'Good' in l])
        if ps_count > 0:
            result['items'].append({
                'name': 'Power Supply',
                'value': f'{ps_count} OK',
                'description': 'Power supply operational status (redundancy recommended)',
                'status': 'warning' if ps_count < 2 else 'normal'
            })
            
            if ps_count < 2:
                self.findings['warning'].append({
                    'category': 'Environment',
                    'issue': 'No power redundancy',
                    'impact': 'Service interruption if power supply fails',
                    'action': 'Install second power supply unit recommended'
                })
        
        self.detailed_results['environment'] = result
    
    def analyze_platform_resources(self):
        """Analyze platform resources"""
        command = 'show platform resources'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # DRAM
        dram_match = re.search(r'DRAM.*?(\d+)%', section)
        if dram_match:
            dram_pct = int(dram_match.group(1))
            status = 'critical' if dram_pct > 90 else ('warning' if dram_pct > 80 else 'normal')
            
            result['items'].append({
                'name': 'DRAM Usage',
                'value': f'{dram_pct}%',
                'description': 'Data plane memory (packet buffers, hardware tables)',
                'status': status
            })
        
        # Flash
        flash_match = re.search(r'Flash.*?(\d+)%', section)
        if flash_match:
            flash_pct = int(flash_match.group(1))
            status = 'warning' if flash_pct > 80 else 'normal'
            
            result['items'].append({
                'name': 'Flash Usage',
                'value': f'{flash_pct}%',
                'description': 'Storage for IOS images and configuration files',
                'status': status
            })
            
            if flash_pct > 80:
                self.findings['warning'].append({
                    'category': 'Storage',
                    'issue': f'Flash storage low ({flash_pct}%)',
                    'impact': 'Cannot upgrade IOS, configuration backup may fail',
                    'action': 'Delete unnecessary files (old IOS images, core dumps)'
                })
        
        self.detailed_results['platform_resources'] = result
    
    def analyze_interfaces_errors(self):
        """Analyze interface errors"""
        command = 'show interfaces counters errors'
        section = self._get_section(command)
        result = self._init_result(command)
        
        error_ports = []
        for line in section.split('\n'):
            if line.strip() and not line.startswith('Port'):
                parts = line.split()
                if len(parts) >= 7:
                    port = parts[0]
                    try:
                        # Error counters
                        errors = [int(p) for p in parts[1:7] if p.isdigit()]
                        if any(e > 0 for e in errors):
                            error_ports.append(port)
                    except:
                        pass
        
        if error_ports:
            result['items'].append({
                'name': 'Ports with Errors',
                'value': f'{len(error_ports)} ports',
                'description': f'Ports with communication errors: {", ".join(error_ports[:5])}',
                'status': 'warning' if len(error_ports) < 5 else 'critical'
            })
            
            self.findings['warning'].append({
                'category': 'Network',
                'issue': f'{len(error_ports)} ports have errors',
                'impact': 'Packet loss, retransmission, performance degradation',
                'action': 'Replace cables, check SFP modules, verify duplex/speed settings'
            })
        else:
            result['items'].append({
                'name': 'Ports with Errors',
                'value': 'None',
                'description': 'All ports normal',
                'status': 'normal'
            })
        
        self.detailed_results['interfaces_errors'] = result
    
    def analyze_obfl_uptime(self):
        """Analyze OBFL reboot history"""
        command = 'show logging onboard switch 1 uptime detail'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Reboot count
        reboot_count = section.count('REBOOT')
        if reboot_count > 0:
            result['items'].append({
                'name': 'Total Reboots',
                'value': f'{reboot_count} times',
                'description': 'Number of reboots recorded in OBFL',
                'status': 'warning' if reboot_count > 10 else 'normal'
            })
            
            if reboot_count > 10:
                self.findings['warning'].append({
                    'category': 'Reliability',
                    'issue': f'Frequent reboots ({reboot_count} times)',
                    'impact': 'System instability, root cause investigation required',
                    'action': 'Analyze reboot patterns, check power/temperature/software issues'
                })
        
        # Recent downtime
        downtime_match = re.search(r'Total Downtime.*?(\d+:\d+:\d+)', section)
        if downtime_match:
            result['items'].append({
                'name': 'Cumulative Downtime',
                'value': downtime_match.group(1),
                'description': 'Total service interruption time due to reboots',
                'status': 'normal'
            })
        
        self.detailed_results['obfl_uptime'] = result
    
    def analyze_obfl_messages(self):
        """Analyze OBFL hardware messages"""
        command = 'show logging onboard switch 1 message'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Temperature sensor errors
        if 'PLATFORM_COLD_ERROR' in section:
            count = section.count('PLATFORM_COLD_ERROR')
            result['items'].append({
                'name': 'Temperature Sensor Error',
                'value': f'{count} times',
                'description': 'Temperature sensor malfunction (abnormal values like -201°C)',
                'status': 'critical'
            })
            
            self.findings['critical'].append({
                'category': 'Hardware',
                'issue': f'Temperature sensor error ({count} occurrences)',
                'impact': 'Hardware fault, cannot monitor temperature, may miss overheating',
                'action': 'RMA request required, open Cisco TAC case'
            })
        
        # FEP errors
        if 'FEP_UNRESP' in section or 'PLATFORM_FEP_UNRESP' in section:
            result['items'].append({
                'name': 'FEP Error',
                'value': 'Detected',
                'description': 'Front End Processor not responding (ASIC communication failure)',
                'status': 'critical'
            })
            
            self.findings['critical'].append({
                'category': 'Hardware',
                'issue': 'FEP (Front End Processor) not responding',
                'impact': 'Packet forwarding failure, port down, complete service disruption possible',
                'action': 'Open TAC case immediately, request RMA'
            })
        
        # Fan errors
        if 'PSFAN' in section:
            result['items'].append({
                'name': 'Fan Error',
                'value': 'Detected',
                'description': 'Power supply fan related error',
                'status': 'critical'
            })
            
            self.findings['critical'].append({
                'category': 'Hardware',
                'issue': 'Power supply fan error',
                'impact': 'Cooling failure may cause automatic shutdown',
                'action': 'Replace fan, remove dust, improve ventilation'
            })
        
        if not result['items']:
            result['items'].append({
                'name': 'OBFL Messages',
                'value': 'Normal',
                'description': 'No hardware errors',
                'status': 'normal'
            })
        
        self.detailed_results['obfl_messages'] = result
    
    def analyze_obfl_temperature(self):
        """Analyze OBFL temperature history"""
        command = 'show logging onboard switch 1 temperature'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Extract maximum temperatures
        max_temps = []
        for line in section.split('\n'):
            if 'INLET' in line or 'FAN' in line:
                # Extract last number from format "0 - 46    27"
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        max_temp = int(parts[-1])
                        sensor = parts[0]
                        max_temps.append((sensor, max_temp))
                    except:
                        pass
        
        if max_temps:
            for sensor, temp in max_temps[:3]:  # Top 3
                result['items'].append({
                    'name': f'{sensor} Max Temp',
                    'value': f'{temp}°C',
                    'description': 'Recorded maximum temperature',
                    'status': 'warning' if temp > 100 else 'normal'
                })
                
                if temp > 100:
                    self.findings['warning'].append({
                        'category': 'Environment',
                        'issue': f'{sensor} sensor recorded {temp}°C',
                        'impact': 'Past overheating condition, shortened hardware lifespan',
                        'action': 'Improve cooling environment'
                    })
        
        self.detailed_results['obfl_temperature'] = result
    
    def analyze_obfl_voltage(self):
        """Analyze OBFL voltage history"""
        command = 'show logging onboard switch 1 voltage'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Voltage anomaly detection
        if section and len(section.split('\n')) > 5:
            result['items'].append({
                'name': 'Voltage History',
                'value': 'Records exist',
                'description': 'Voltage data stored in OBFL',
                'status': 'normal'
            })
        else:
            result['items'].append({
                'name': 'Voltage History',
                'value': 'No data',
                'description': 'No voltage anomalies detected',
                'status': 'normal'
            })
        
        self.detailed_results['obfl_voltage'] = result
    
    def analyze_reload(self):
        """Analyze scheduled reload"""
        command = 'show reload'
        section = self._get_section(command)
        result = self._init_result(command)
        
        if 'Reload scheduled' in section:
            result['items'].append({
                'name': 'Reload Schedule',
                'value': 'Yes',
                'description': 'Scheduled reload exists',
                'status': 'warning'
            })
            
            self.findings['info'].append({
                'category': 'System',
                'issue': 'Reload scheduled',
                'impact': 'Service interruption at scheduled time',
                'action': 'Verify reload time and announce affected areas'
            })
        else:
            result['items'].append({
                'name': 'Reload Schedule',
                'value': 'None',
                'description': 'No scheduled reload',
                'status': 'normal'
            })
        
        self.detailed_results['reload'] = result
    
    def analyze_error_logs(self):
        """Analyze filtered error logs"""
        command = 'show logging | include error|crash|fail|down'
        section = self._get_section(command)
        result = self._init_result(command)
        
        error_count = len([l for l in section.split('\n') if l.strip()])
        
        result['items'].append({
            'name': 'Error Messages',
            'value': f'{error_count} messages',
            'description': 'Log lines containing error/crash/fail/down keywords',
            'status': 'warning' if error_count > 50 else 'normal'
        })
        
        # LINK-3-UPDOWN messages (interface down)
        link_down_count = section.count('LINK-3-UPDOWN')
        if link_down_count > 0:
            result['items'].append({
                'name': 'Link Down Events',
                'value': f'{link_down_count} times',
                'description': 'Number of times interfaces transitioned to Down state',
                'status': 'warning' if link_down_count > 10 else 'normal'
            })
        
        self.detailed_results['error_logs'] = result
    
    def analyze_routing(self):
        """Analyze routing table"""
        command = 'show ip route summary'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Total routes
        total_match = re.search(r'Total\s+(\d+)\s+(\d+)', section)
        if total_match:
            routes = int(total_match.group(2))
            result['items'].append({
                'name': 'Total Routes',
                'value': f'{routes} routes',
                'description': 'Routes registered in routing table (connected + static + dynamic)',
                'status': 'normal'
            })
        
        # Connected routes
        connected_match = re.search(r'connected\s+(\d+)\s+(\d+)', section)
        if connected_match:
            connected = int(connected_match.group(2))
            result['items'].append({
                'name': 'Connected Routes',
                'value': f'{connected} routes',
                'description': 'Number of directly connected networks (interface IPs)',
                'status': 'normal'
            })
        
        # Static routes
        static_match = re.search(r'static\s+(\d+)\s+(\d+)', section)
        if static_match:
            static = int(static_match.group(2))
            result['items'].append({
                'name': 'Static Routes',
                'value': f'{static} routes',
                'description': 'Manually configured fixed routes',
                'status': 'normal'
            })
        
        self.detailed_results['routing'] = result
    
    def analyze_arp(self):
        """Analyze ARP table"""
        command = 'show arp summary'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Total ARP entries
        total_match = re.search(r'Total number of entries in the ARP table: (\d+)', section)
        if total_match:
            arp_count = int(total_match.group(1))
            result['items'].append({
                'name': 'ARP Entries',
                'value': f'{arp_count} entries',
                'description': 'Known IP-MAC mappings (connected hosts)',
                'status': 'normal'
            })
        
        # Incomplete ARP
        incomplete_match = re.search(r'Total number of Incomplete ARP entries: (\d+)', section)
        if incomplete_match:
            incomplete = int(incomplete_match.group(1))
            result['items'].append({
                'name': 'Incomplete ARP',
                'value': f'{incomplete} entries',
                'description': 'Hosts not responding to ARP requests (cannot communicate)',
                'status': 'warning' if incomplete > 10 else 'normal'
            })
            
            if incomplete > 10:
                self.findings['warning'].append({
                    'category': 'Network',
                    'issue': f'Many incomplete ARP entries ({incomplete} entries)',
                    'impact': 'Some hosts are not responding or removed from network',
                    'action': 'Clear ARP table, verify host connectivity'
                })
        
        self.detailed_results['arp'] = result
    
    def analyze_mac_table(self):
        """Analyze MAC address table"""
        command = 'show mac address-table count'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Total MAC addresses
        total_match = re.search(r'Total Dynamic Address Count\s+:\s+(\d+)', section)
        if total_match:
            mac_count = int(total_match.group(1))
            result['items'].append({
                'name': 'Learned MAC Addresses',
                'value': f'{mac_count} addresses',
                'description': 'Number of dynamically learned MAC addresses (connected devices)',
                'status': 'normal'
            })
        
        # MAC by VLAN
        vlan_macs = re.findall(r'Vlan (\d+).*?Total Mac Addresses\s+:\s+(\d+)', section, re.DOTALL)
        if vlan_macs:
            vlan_list = ', '.join([f'VLAN{v}: {c}' for v, c in vlan_macs[:3]])
            result['items'].append({
                'name': 'Distribution by VLAN',
                'value': vlan_list,
                'description': 'MAC addresses learned per VLAN',
                'status': 'normal'
            })
        
        self.detailed_results['mac_table'] = result
    
    def analyze_interfaces_status(self):
        """Analyze interface status"""
        command = 'show interfaces status'
        section = self._get_section(command)
        result = self._init_result(command)
        
        connected = notconnect = err_disabled = 0
        
        for line in section.split('\n'):
            if 'connected' in line.lower():
                connected += 1
            elif 'notconnect' in line.lower():
                notconnect += 1
            elif 'err-disabled' in line.lower():
                err_disabled += 1
        
        result['items'].append({
            'name': 'Connected Ports',
            'value': f'{connected} ports',
            'description': 'Currently active and communicating ports',
            'status': 'normal'
        })
        
        result['items'].append({
            'name': 'Disconnected Ports',
            'value': f'{notconnect} ports',
            'description': 'Ports without cables connected',
            'status': 'normal'
        })
        
        if err_disabled > 0:
            result['items'].append({
                'name': 'Err-disabled Ports',
                'value': f'{err_disabled} ports',
                'description': 'Ports auto-disabled due to errors (security/loop detection)',
                'status': 'critical'
            })
            
            self.findings['critical'].append({
                'category': 'Network',
                'issue': f'{err_disabled} ports are err-disabled',
                'impact': 'Those ports cannot communicate (loop, port security violation, BPDU guard, etc.)',
                'action': 'Identify cause then recover with "shutdown" + "no shutdown"'
            })
        
        self.detailed_results['interfaces_status'] = result
    
    def analyze_interfaces_description(self):
        """Analyze interface descriptions"""
        command = 'show interfaces description'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Number of interfaces with descriptions
        described = len([l for l in section.split('\n') if l.strip() and not l.startswith('Interface')])
        
        result['items'].append({
            'name': 'Ports with Descriptions',
            'value': f'{described} ports',
            'description': 'Number of interfaces with description configured',
            'status': 'normal'
        })
        
        self.detailed_results['interfaces_description'] = result
    
    def analyze_tcam(self):
        """Analyze TCAM resources"""
        command = 'show platform hardware fed switch active fwd-asic resource tcam utilization'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Extract TCAM usage
        tcam_usage = []
        for line in section.split('\n'):
            if '%' in line and 'Used' in line:
                match = re.search(r'(\d+)%', line)
                if match:
                    pct = int(match.group(1))
                    tcam_usage.append(pct)
        
        if tcam_usage:
            max_usage = max(tcam_usage)
            result['items'].append({
                'name': 'Max TCAM Usage',
                'value': f'{max_usage}%',
                'description': 'TCAM table usage (ACL, routing, etc.)',
                'status': 'critical' if max_usage > 90 else ('warning' if max_usage > 80 else 'normal')
            })
            
            if max_usage > 90:
                self.findings['critical'].append({
                    'category': 'TCAM',
                    'issue': f'TCAM resource exhaustion risk ({max_usage}%)',
                    'impact': 'Cannot add new ACL/routes, packets processed in software causing performance degradation',
                    'action': 'Optimize ACLs, remove unnecessary policies, reallocate TCAM regions'
                })
        
        self.detailed_results['tcam'] = result
    
    def analyze_control_processor(self):
        """Analyze control processor status"""
        command = 'show platform software status control-processor brief'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Load average
        load_match = re.search(r'Load Average.*?([\d.]+)', section)
        if load_match:
            load = float(load_match.group(1))
            result['items'].append({
                'name': 'Load Average',
                'value': f'{load}',
                'description': 'System load (overloaded if greater than 1)',
                'status': 'warning' if load > 1.0 else 'normal'
            })
        
        self.detailed_results['control_processor'] = result
    
    def analyze_inventory(self):
        """Analyze hardware inventory"""
        command = 'show inventory'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Model
        model_match = re.search(r'PID:\s*(\S+)', section)
        if model_match:
            result['items'].append({
                'name': 'Model',
                'value': model_match.group(1),
                'description': 'Device Product ID',
                'status': 'normal'
            })
        
        # Serial number
        sn_match = re.search(r'SN:\s*(\S+)', section)
        if sn_match:
            result['items'].append({
                'name': 'Serial Number',
                'value': sn_match.group(1),
                'description': 'Required for RMA and support requests',
                'status': 'normal'
            })
        
        self.detailed_results['inventory'] = result
    
    def analyze_redundancy(self):
        """Analyze redundancy status"""
        command = 'show redundancy'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Redundancy Mode
        mode_match = re.search(r'Operating Redundancy Mode\s*=\s*(.+)', section)
        if mode_match:
            mode = mode_match.group(1).strip()
            result['items'].append({
                'name': 'Redundancy Mode',
                'value': mode,
                'description': 'Redundancy mode (Non-redundant = no redundancy)',
                'status': 'warning' if 'Non-redundant' in mode else 'normal'
            })
            
            if 'Non-redundant' in mode:
                self.findings['warning'].append({
                    'category': 'Redundancy',
                    'issue': 'No redundancy configured',
                    'impact': 'Service interruption on single point of failure (SPOF)',
                    'action': 'Consider stack configuration or dual supervisor addition'
                })
        
        # Switchover count
        switchover_match = re.search(r'Switchovers\s*=\s*(\d+)', section)
        if switchover_match:
            count = int(switchover_match.group(1))
            if count > 0:
                result['items'].append({
                    'name': 'Switchovers',
                    'value': f'{count} times',
                    'description': 'Number of Active/Standby transitions',
                    'status': 'warning' if count > 3 else 'normal'
                })
        
        self.detailed_results['redundancy'] = result
    
    def analyze_switch_stack(self):
        """Analyze switch stack status"""
        command = 'show switch'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Stack member count
        members = len([l for l in section.split('\n') if l.strip() and l[0].isdigit()])
        
        if members > 1:
            result['items'].append({
                'name': 'Stack Members',
                'value': f'{members} switches',
                'description': 'Number of switches connected in stack',
                'status': 'normal'
            })
        elif members == 1:
            result['items'].append({
                'name': 'Stack Configuration',
                'value': 'Standalone',
                'description': 'Operating as single switch without stack',
                'status': 'normal'
            })
        
        # Version mismatch check
        version_detail = self._get_section('show switch detail')
        versions = re.findall(r'Version\s*:\s*([\d.]+)', version_detail)
        if len(set(versions)) > 1:
            self.findings['warning'].append({
                'category': 'Stack',
                'issue': 'IOS version mismatch among stack members',
                'impact': 'Stack instability, feature limitations, possible reboot',
                'action': 'Upgrade all members to same IOS version'
            })
        
        self.detailed_results['switch_stack'] = result
    
    def analyze_crashinfo(self):
        """Analyze crash information"""
        command = 'dir crashinfo:'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Find crashinfo files
        crashinfo_files = [l for l in section.split('\n') if 'crashinfo' in l.lower() and '-rw' in l]
        
        if crashinfo_files:
            # Only non-zero files
            non_zero = [f for f in crashinfo_files if ' 0 ' not in f]
            if non_zero:
                result['items'].append({
                    'name': 'Crash Files',
                    'value': f'{len(non_zero)} found',
                    'description': 'Software crash dump files exist',
                    'status': 'critical'
                })
                
                self.findings['critical'].append({
                    'category': 'Reliability',
                    'issue': f'{len(non_zero)} crash dump files found',
                    'impact': 'Past software crashes occurred, recurrence possible',
                    'action': 'Provide crashinfo files to TAC for analysis'
                })
            else:
                result['items'].append({
                    'name': 'Crash Files',
                    'value': 'None',
                    'description': 'No crash history',
                    'status': 'normal'
                })
        else:
            result['items'].append({
                'name': 'Crash Files',
                'value': 'None',
                'description': 'No crash history',
                'status': 'normal'
            })
        
        self.detailed_results['crashinfo'] = result
    
    def analyze_stacks(self):
        """Analyze stack traces"""
        command = 'show stacks'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Usually not significant during normal operation
        result['items'].append({
            'name': 'Stack Information',
            'value': 'Collected',
            'description': 'Stack traces for debugging (normal)',
            'status': 'normal'
        })
        
        self.detailed_results['stacks'] = result
    
    def analyze_core_dump(self):
        """Analyze core dumps"""
        command = 'show core'
        section = self._get_section(command)
        result = self._init_result(command)
        
        if 'No core dumps' in section or not section.strip():
            result['items'].append({
                'name': 'Core Dumps',
                'value': 'None',
                'description': 'No process crash history',
                'status': 'normal'
            })
        else:
            result['items'].append({
                'name': 'Core Dumps',
                'value': 'Found',
                'description': 'Process crash history exists',
                'status': 'critical'
            })
            
            self.findings['critical'].append({
                'category': 'Reliability',
                'issue': 'Core dump files found',
                'impact': 'Process crashes occurred, feature failures possible',
                'action': 'Provide core files to TAC for root cause analysis'
            })
        
        self.detailed_results['core_dump'] = result
    
    def analyze_cpu_history(self):
        """Analyze CPU history"""
        command = 'show processes cpu history'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Graph data collected
        result['items'].append({
            'name': 'CPU History',
            'value': 'Collected',
            'description': 'CPU usage patterns over time (graph format)',
            'status': 'normal'
        })
        
        self.detailed_results['cpu_history'] = result
    
    def analyze_cpu_queue(self):
        """Analyze CPU queues"""
        command = 'show platform software fed switch active punt cpuq all'
        section = self._get_section(command)
        result = self._init_result(command)
        
        # Check for packet drops
        drop_found = False
        for line in section.split('\n'):
            if 'Drop' in line or 'drop' in line:
                match = re.search(r'(\d+)', line)
                if match and int(match.group(1)) > 1000:
                    drop_found = True
                    break
        
        if drop_found:
            result['items'].append({
                'name': 'CPU Queue Drops',
                'value': 'Detected',
                'description': 'Packets punted to CPU are being dropped (overload)',
                'status': 'warning'
            })
            
            self.findings['warning'].append({
                'category': 'CPU',
                'issue': 'CPU Punt Queue packet drops detected',
                'impact': 'Control Plane packet loss (routing protocols, management traffic)',
                'action': 'Check CoPP (Control Plane Policing) settings, block attack traffic'
            })
        else:
            result['items'].append({
                'name': 'CPU Queue',
                'value': 'Normal',
                'description': 'No packet drops',
                'status': 'normal'
            })
        
        self.detailed_results['cpu_queue'] = result
    
    def generate_markdown_report(self, output_file: Path = None):
        """Generate detailed markdown report"""
        if output_file is None:
            output_file = Path("./log") / f"cisco_diagnostic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        output_file.parent.mkdir(exist_ok=True)
        
        with open(output_file, 'w') as f:
            # Title
            f.write("# 🔍 Cisco Network Device Comprehensive Diagnostic Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary
            f.write("---\n\n")
            f.write("## 📊 Diagnostic Summary\n\n")
            
            critical_count = len(self.findings['critical'])
            warning_count = len(self.findings['warning'])
            
            if critical_count > 0:
                status_emoji = "🔴"
                status_text = "Critical Issues Found"
            elif warning_count > 0:
                status_emoji = "⚠️"
                status_text = "Warnings Detected"
            else:
                status_emoji = "✅"
                status_text = "Normal"
            
            f.write(f"**Overall Status:** {status_emoji} {status_text}\n\n")
            f.write(f"- 🔴 **Critical Issues:** {critical_count}\n")
            f.write(f"- ⚠️ **Warnings:** {warning_count}\n\n")
            
            # Critical issues
            if self.findings['critical']:
                f.write("### 🔴 Immediate Action Required (Critical)\n\n")
                f.write("| Category | Issue | Impact | Recommended Action |\n")
                f.write("|----------|-------|--------|-----------------|\n")
                for finding in self.findings['critical']:
                    f.write(f"| {finding['category']} | {finding['issue']} | {finding['impact']} | {finding['action']} |\n")
                f.write("\n")
            
            # Warnings
            if self.findings['warning']:
                f.write("### ⚠️ Attention Required (Warning)\n\n")
                f.write("| Category | Issue | Impact | Recommended Action |\n")
                f.write("|----------|-------|--------|-----------------|\n")
                for finding in self.findings['warning']:
                    f.write(f"| {finding['category']} | {finding['issue']} | {finding['impact']} | {finding['action']} |\n")
                f.write("\n")
            
            f.write("---\n\n")
            
            # Detailed analysis results
            f.write("## 📋 Detailed Analysis Results\n\n")
            f.write("Detailed explanations and current status for each item.\n\n")
            
            for key, result in self.detailed_results.items():
                if not result.get('items'):
                    continue
                
                f.write(f"### {result['title']}\n\n")
                f.write(f"**Description:** {result['description']}\n\n")
                
                # Display source command if available
                if 'command' in result:
                    f.write(f"**Source Command:** `{result['command']}`\n\n")
                
                f.write("| Item | Current Value | Description | Status |\n")
                f.write("|------|---------------|-------------|--------|\n")
                
                for item in result['items']:
                    status_emoji_map = {
                        'normal': '✅',
                        'warning': '⚠️',
                        'critical': '🔴'
                    }
                    emoji = status_emoji_map.get(item.get('status', 'normal'), '✅')
                    
                    f.write(f"| {item['name']} | {item['value']} | {item['description']} | {emoji} |\n")
                
                f.write("\n")
            
            # Recommendations
            f.write("---\n\n")
            f.write("## 💡 Comprehensive Recommendations\n\n")
            
            if not self.findings['critical'] and not self.findings['warning']:
                f.write("### ✅ System Normal\n\n")
                f.write("All items are within normal range. Continue regular monitoring.\n\n")
            else:
                f.write("### Action Plan by Priority\n\n")
                
                if self.findings['critical']:
                    f.write("#### 🔴 Urgent (Within 24 hours)\n\n")
                    for i, finding in enumerate(self.findings['critical'], 1):
                        f.write(f"{i}. **[{finding['category']}]** {finding['issue']}\n")
                        f.write(f"   - **Action:** {finding['action']}\n\n")
                
                if self.findings['warning']:
                    f.write("#### ⚠️ Important (Within 1 week)\n\n")
                    for i, finding in enumerate(self.findings['warning'], 1):
                        f.write(f"{i}. **[{finding['category']}]** {finding['issue']}\n")
                        f.write(f"   - **Action:** {finding['action']}\n\n")
            
            # Reference information
            f.write("---\n\n")
            f.write("## 📚 References\n\n")
            f.write("### Cisco Official Resources\n\n")
            f.write("- [Cisco TAC Support](https://www.cisco.com/c/en/us/support/index.html)\n")
            f.write("- [Software Download](https://software.cisco.com/)\n")
            f.write("- [Bug Search Tool](https://bst.cloudapps.cisco.com/)\n")
            f.write("- [Field Notices](https://www.cisco.com/c/en/us/support/docs/field-notices/)\n\n")
            
            f.write("### Emergency Contacts\n\n")
            f.write("- **Cisco TAC Korea:** +82-2-3429-8200\n")
            f.write("- **Verify SmartNet contract**\n\n")
            
            f.write("---\n\n")
            f.write("*This report was automatically generated. Please consult with experts for accurate diagnosis.*\n")
        
        print(f"\n✅ Diagnostic report generated: {output_file}")
        return output_file
