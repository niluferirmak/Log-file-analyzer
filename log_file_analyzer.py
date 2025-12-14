import re
import collections
import os

def analyze_log_file(file_path):
    if not os.path.isfile(file_path):
        
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
   
    log_pattern = re.compile(r'^(?P<ip>\S+) - - \[(?P<date_time>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+|-)')
    
    status_counter = collections.Counter()
    total_requests = 0
    total_bytes = 0
    ip_counter = collections.Counter()
    date_counter = collections.Counter() 

    try:
        with open(file_path, 'r', encoding='latin-1') as file:
            for line in file:
                match = log_pattern.match(line)
                if match:
                    total_requests += 1
                    status = match.group('status')
                    size = match.group('size')
                    ip = match.group('ip')
                    date = match.group('date_time').split(':')[0] 

                    status_counter[status] += 1
                    ip_counter[ip] += 1
                    date_counter[date] += 1

                    if size != '-':
                        total_bytes += int(size)
        
        log_data = {
            'total_requests': total_requests,
            'total_bytes': total_bytes,
            'status_counter': status_counter,
            'ip_counter': ip_counter,
            'date_counter': date_counter,
            'most_common_ips': ip_counter.most_common(5)
        }
        return log_data

    except Exception as e:
        raise RuntimeError(f"An error occurred while processing the file: {e}")


def detect_anomalies(log_data):
    anomalies = []
    for status, count in log_data['status_counter'].items():
        if status.startswith('5') and count > 50:  # Example threshold
            anomalies.append(f"High number of server errors: {count} occurrences of status {status}")
    return anomalies


def error_based_analysis(status_counter):
    error_analysis = {}
    for status, count in status_counter.items():
        if status.startswith('4') or status.startswith('5'):
            error_analysis[status] = count
    return error_analysis


def generate_report(log_data, anomalies, error_analysis):
    print("---Log Analysis Report---", "\n")
    print(f"Total Requests: {log_data['total_requests']}")
    print(f"Total Bytes Transferred: {log_data['total_bytes']}")
    print("\nStatus Code Distribution:")
    for status, count in log_data['status_counter'].items():
        print(f"  {status}: {count}")
    
    print("\nTop 5 IP Addresses:")
    for ip, count in log_data['most_common_ips']:
        print(f"  {ip}: {count} requests")
    
    print("\nAnomalies Detected:")
    if anomalies:
        for anomaly in anomalies:
            print(f"  - {anomaly}")
    else:
        print("  None")
    
    print("\nError-Based Analysis:")
    for status, count in error_analysis.items():
        print(f"  {status}: {count} errors")


if __name__ == "__main__":
    log_file_path = 'access.log'  # Replace with your log file path
    log_data = analyze_log_file(log_file_path)
    anomalies = detect_anomalies(log_data)
    error_analysis = error_based_analysis(log_data['status_counter'])
    generate_report(log_data, anomalies, error_analysis)
