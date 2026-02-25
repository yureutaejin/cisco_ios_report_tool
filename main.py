import sys
import os
import json

from modules.collector import CiscoCollector
from modules.analyzer import CiscoAnalyzer

from dotenv import load_dotenv

def main():

    load_dotenv()
    with open('command_info.json', 'r') as f:
        COMMAND_INFO = json.load(f)
    
    collector = CiscoCollector(
        hostname=os.getenv("CISCO_HOST"),
        username=os.getenv("CISCO_CONSOLE_USERNAME"),
        password=os.getenv("CISCO_CONSOLE_PASSWD"),
        enable_password=os.getenv("CISCO_CONSOLE_ENABLE_PASSWD"),
        command_info=COMMAND_INFO['COMMAND_INFO']
    )
    if collector.connect():
        collected_data = collector.collect_all()
        collector.save_raw_data()
        collector.disconnect()
        analyzer = CiscoAnalyzer(collected_data, command_info=COMMAND_INFO['COMMAND_INFO'])
        
        analyzer.generate_markdown_report(analyzer.analyze_all())

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
