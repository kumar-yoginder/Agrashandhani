"""
Input Handler for CLI and CSV inputs
"""
import csv
from validators import IOCValidator


class InputHandler:
    """Handle input from CLI and CSV files"""
    
    @staticmethod
    def read_csv(filepath: str) -> list:
        """Read IOCs from CSV file"""
        iocs = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Try to detect if it has headers
                sample = f.readline()
                f.seek(0)
                
                # Simple detection: if first line has common header keywords
                is_header = any(keyword in sample.lower() for keyword in ['ioc', 'query', 'indicator', 'hash', 'ip', 'domain'])
                
                reader = csv.reader(f)
                if is_header:
                    next(reader)  # Skip header row
                
                for row in reader:
                    if row and row[0].strip():  # Non-empty first column
                        iocs.append(row[0].strip())
            
            return iocs
        except Exception as e:
            print(f"Error reading CSV: {e}")
            return []
    
    @staticmethod
    def validate_inputs(iocs: list) -> dict:
        """Validate and classify inputs"""
        results = {
            "valid": [],
            "invalid": [],
            "summary": {}
        }
        
        for ioc in iocs:
            if not ioc.strip():
                continue
            
            classification = IOCValidator.classify(ioc)
            
            if classification["type"] != "unknown":
                results["valid"].append(classification)
                # Track count by type
                ioc_type = classification["type"]
                results["summary"][ioc_type] = results["summary"].get(ioc_type, 0) + 1
            else:
                results["invalid"].append({
                    "value": ioc,
                    "reason": "Could not classify IOC type"
                })
        
        return results
