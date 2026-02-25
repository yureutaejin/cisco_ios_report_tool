import paramiko
import time
from datetime import datetime
from pathlib import Path
from typing import Dict


class CiscoCollector:
    def __init__(self, hostname: str, username: str, password: str, enable_password: str, command_info: Dict):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.enable_password = enable_password or password
        self.client = None
        self.shell = None
        self.collected_data = {}
        self.COMMAND_INFO = command_info
        self.COMMANDS = list(self.COMMAND_INFO.keys())
        
    def connect(self):
        """Establish SSH connection"""
        print(f"🔌 Connecting to {self.hostname}...")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.client.connect(
                self.hostname,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=10,
                auth_timeout=10
            )
            
            # Start interactive shell with optimized settings
            self.shell = self.client.invoke_shell(width=200, height=24)
            self.shell.settimeout(10)

            time.sleep(0.3)
            self._read_until_prompt(timeout=5)
            
            # Enter Enable mode
            self._send_command("enable")
            output = self._read_until_prompt(timeout=5)
            if "Password:" in output:
                self._send_command(self.enable_password)
                self._read_until_prompt(timeout=5)
            
            # Disable pagination
            self._send_command("terminal length 0")
            self._read_until_prompt(timeout=5)
            
            print("✅ Connection successful\n")
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def _send_command(self, command: str):
        """Send command"""
        self.shell.send(command + "\n")
        time.sleep(0.05)
    
    def _read_until_prompt(self, timeout: int = 30) -> str:
        """Read until prompt appears"""
        output = ""
        start_time = time.time()
        
        while True:
            if time.time() - start_time > timeout:
                break
                
            if self.shell.recv_ready():
                chunk = self.shell.recv(65535).decode('utf-8', errors='ignore')
                output += chunk
                
                # Check for prompt patterns (>, # etc.)
                if output.strip().endswith('>') or output.strip().endswith('#'):
                    break
            else:
                time.sleep(0.05)
        
        return output
    
    def collect_all(self) -> Dict[str, str]:
        """Collect all diagnostic commands"""
        print(f"📦 Executing {len(self.COMMANDS)} commands...\n")
        
        for i, command in enumerate(self.COMMANDS, 1):
            cmd_info = self.COMMAND_INFO[command]
            print(f"[{i}/{len(self.COMMANDS)}] {command}")
            print(f"    → {cmd_info['description']}")
            
            try:
                self._send_command(command)
                output = self._read_until_prompt(timeout=60)
                
                # Remove command echo
                lines = output.split('\n')
                # Remove first line (command) and last line (prompt)
                clean_output = '\n'.join(lines[1:-1])
                
                self.collected_data[command] = clean_output
                print(f"    ✓ Collected {len(clean_output)} bytes\n")
                
            except Exception as e:
                print(f"    ✗ Failed: {e}\n")
                self.collected_data[command] = f"Error: {e}"
        
        return self.collected_data
    
    def disconnect(self):
        """Close connection"""
        if self.shell:
            self.shell.close()
        if self.client:
            self.client.close()
        print("\n🔌 Connection closed")
    
    def save_raw_data(self, output_dir: Path = None):
        """Save collected data to file"""
        if output_dir is None:
            output_dir = Path("./log")
        
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"cisco_collected_{timestamp}.txt"
        
        with open(output_file, 'w') as f:
            f.write(f"Cisco Diagnostic Data Collection\n")
            f.write(f"Collected from: {self.hostname}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for command, output in self.collected_data.items():
                f.write(f"\n{'=' * 80}\n")
                f.write(f"=== {command} ===\n")
                f.write(f"{'=' * 80}\n\n")
                f.write(output)
                f.write("\n\n")
        
        print(f"\n💾 Raw data saved: {output_file}")
        return output_file

if __name__ == "__main__":
    # Example usage
    collector = CiscoCollector(
        hostname="",
        username="",
        password="",
        enable_password="",
        command_info={}
    )
    if collector.connect():
        collector.collect_all()
        collector.save_raw_data()
        collector.disconnect()
