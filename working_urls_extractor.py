import pandas as pd
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_url_status(url):
    try:
        response = requests.get(url, timeout=10)
        return url, response.status_code
    except requests.RequestException as e:
        return url, None

def check_urls(csv_file, output_file, batch_size=1000, max_workers=20):
    # Read the CSV file in chunks
    url_chunks = pd.read_csv(csv_file, chunksize=batch_size)

    valid_urls = []

    # Process each chunk
    for chunk in url_chunks:
        # Ensure all URLs start with "https://"
        urls = ['https://' + url if not url.startswith('http') else url for url in chunk['url'].tolist()]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(check_url_status, url): url for url in urls}

            for future in as_completed(future_to_url):
                url, status_code = future.result()
                if status_code is not None:
                    print(f"URL: {url} - Status Code: {status_code}")
                    if status_code == 200:
                        valid_urls.append(url)
                else:
                    print(f"URL: {url} - Invalid URL or Request Exception")

    # Write valid URLs to a text file
    with open(output_file, 'w') as f:
        for url in valid_urls:
            f.write(url + '\n')

# Example usage
csv_file = 'urls.csv'
output_file = 'urls.txt'
check_urls(csv_file, output_file)
