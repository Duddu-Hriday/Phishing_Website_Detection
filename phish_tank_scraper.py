import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime
import re
import time
from concurrent.futures import ThreadPoolExecutor
import csv

non_scrape_pages = []

def threshold_time(file):
    if os.path.exists(file):
        with open(file, 'r') as f:
            return f.read()
    return "2000-01-01 00:00:00"

def html_file(day, url, page, dir):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Get the HTML content
            html_content = response.text

            os.makedirs(dir, exist_ok=True)
            
            # Define the output file path
            output_file_path = os.path.join(dir, f'{day}_output_{page}.html')

            # Write the HTML content to the file
            with open(output_file_path, 'w', encoding='utf-8') as file:
                file.write(html_content)
            print(f"HTML content has been saved to {output_file_path}")
            return output_file_path
        else:
            non_scrape_pages.append(page)
            print(f"Non 200 Status code: {response.status_code}")
            return ""
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        non_scrape_pages.append(page)
        return ""


def extract_time(input_string):
    pattern = r"(\w+ \d{1,2}[a-z]{2} \d{4} \d{1,2}:\d{2} [APM]{2})"
    match = re.search(pattern, input_string)

    date_str = match.group(1)

    # Remove the ordinal suffix (st, nd, rd, th) from the day
    date_str = re.sub(r'(\d{1,2})[a-z]{2}', r'\1', date_str)

    # Parse the date string into a datetime object
    date_time_obj = datetime.strptime(date_str, "%b %d %Y %I:%M %p")

    # Use the extracted date and time for future usage
    formatted_date_time = date_time_obj.strftime("%Y-%m-%d %H:%M:%S")
    print("Formatted Date and Time:", formatted_date_time)
    return formatted_date_time

def remove_last_part_of_url(url):
    if not (str(url).startswith('https://') or str(url).startswith('http://')):
        url = 'https://' + url

    suffix = '...added'
    if url.endswith(suffix):
        return url[:-len(suffix)]
    if url.endswith('added'):
        return url[:-len('added')]
    return url
    # Parse the URL into components
    # parts = urlsplit(url)
    
    # # Split the path into parts and remove the last part
    # path_parts = parts.path.split('/')
    # if path_parts[-1] == '':
    #     path_parts = path_parts[:-2]  # Remove the last empty part and the preceding part
    # else:
    #     path_parts = path_parts[:-1]  # Remove just the last part
    
    # # Join the remaining path parts back together
    # new_path = '/'.join(path_parts)
    
    # # Reconstruct the URL with the new path
    # new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
    
    # if new_url[-5:] == '.html':
    #     return new_url
    # return new_url + '/'

def scraping(html):
    if not os.path.exists(html):
        print(f"File {html} does not exist")
        return
    
    with open(html, 'r') as f:
        html_doc = f.read()

    soup = BeautifulSoup(html_doc, 'html.parser')
    table = soup.find('table')
    count = 0
    urls = []
    valid_phish = []
    online = []
    time_list = []
    for tr in table.find_all('tr'):
        if count == 0:
            count = 1
            continue
        td = tr.find_all('td')
        span = td[1].find_all('span')
        formatted_time = extract_time(span[0].text)
        time_list.append(formatted_time)
        url = td[1].get_text(strip=True).split()[0]
        new_url = remove_last_part_of_url(url)
        try:
            response = requests.get(new_url, timeout=10)
            if not response.status_code == 200:
                print('Phishing site: Status code not 200')
                continue
            print("Phishing site returns 200")
            urls.append(new_url)
            valid_phish.append(td[3])
            online.append(td[4])
        except requests.RequestException:
            print('Phishing site: Unable to get response')
            continue


    cutoff_date_str = threshold_time('time_old.txt')
    print('cutoff = ' + cutoff_date_str)
    cutoff_date = datetime.strptime(cutoff_date_str, "%Y-%m-%d %H:%M:%S")
    
    with open('phishing_urls.csv', 'a') as f:
        for i in range(len(urls)):
            current_time = datetime.strptime(time_list[i], "%Y-%m-%d %H:%M:%S")
            if current_time > cutoff_date:
                f.write(urls[i] + "," + valid_phish[i].text + "," + online[i].text + ',' + time_list[i] + '\n')
            else:
                print("Already Exists in the csv file")


def extract_most_recent_timestamp(csv_file):
    most_recent_time = None
    
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            timestamp_str = row[-1]
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            if most_recent_time is None or timestamp > most_recent_time:
                most_recent_time = timestamp
    
    return most_recent_time

def fetch_and_scrape_page(day, page):
    url = f"https://phishtank.org/phish_search.php?page={page}&valid=y&Search=Search"
    html = html_file(day, url, page, 'fetch_phishing_data')
    scraping(html)
    time.sleep(1)

day = 0
pages = 1000

start_time = time.time()
with ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(fetch_and_scrape_page, day, page) for page in range(pages)]
    
    # Ensure all threads have completed
    for future in futures:
        try:
            future.result()
        except Exception as e:
            print(f"Thread resulted in an error: {e}")

end_time =  time.time()


most_recent_timestamp = extract_most_recent_timestamp("phishing_urls.csv")

with open('time_old.txt', 'w') as file:
    file.write(most_recent_timestamp.strftime('%Y-%m-%d %H:%M:%S'))

print(f"The most recent timestamp {most_recent_timestamp} has been written to time_old.txt.")

with open('non_scraping.txt', 'w') as f:
    for page in non_scrape_pages:
        f.write(str(page) + "\n")


print("Total Time taken = "+str(end_time - start_time))
