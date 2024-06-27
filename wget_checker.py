import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import random

# Function to read URLs from a file
def read_urls_from_file(file_path):
    with open(file_path, 'r') as f:
        urls = f.readlines()
    # Strip newline characters from each URL
    urls = [url.strip() for url in urls]
    return urls

# Function to check if URL can be successfully downloaded using wget
def check_url_with_wget(url, user_agent):
    command = ['wget', '--spider', '--quiet', '-U', user_agent, url]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        return False

# Main function to process URLs
def main(input_file, output_file):
    # Read URLs from input file
    urls = read_urls_from_file(input_file)
    
    # List of user agents to rotate
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3', 
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        # Add more user agents as needed
    ]
    
    # Open output file for writing successful URLs with line buffering
    with open(output_file, 'a', buffering=1) as out_file:
        
        # Define a lock to synchronize file writes
        lock = threading.Lock()
        
        # Success count
        success_count = 0
        
        def process_url(url):
            nonlocal success_count
            user_agent = random.choice(user_agents)
            if check_url_with_wget(url, user_agent):
                with lock:
                    out_file.write(url + '\n')
                    out_file.flush()
                    success_count += 1
                    print(f'Successfully downloaded: {url}')
                    return True
            else:
                print(f'Failed to download: {url}')
            return False

        # Use ThreadPoolExecutor to process URLs in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(process_url, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f'Error processing URL: {futures[future]} with error: {e}')

if __name__ == "__main__":
    input_file = 'urls.txt'  # Replace with your input file path
    output_file = 'valid_urls.txt'  # Replace with your output file path
    
    main(input_file, output_file)
