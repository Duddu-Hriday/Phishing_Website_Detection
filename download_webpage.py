'''
    Code written by Duddu Hriday, 4th Year student at IIT Dharwad
    This code is a part of a project on Phishing website detection with Professor Tamal Das and Aditya Kulkarni
    This code does the following things:
    - Download webpage using wget
    - Download required resources like css, js, images, other files using requests Library
    - Change the path pointed to the server in the html file to the local path to load them even when offline
'''
##----Threading Included
##-----All resources download

import subprocess
import os
import requests
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
import tldextract
import chardet
import time
from requests.exceptions import SSLError, ConnectionError, Timeout
import logging
import random
from selenium import webdriver

from PIL import Image
import time

import cv2
from skimage.metrics import structural_similarity as ssim

import threading

from selenium.common.exceptions import TimeoutException

import shutil

import pandas
import csv
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# def modify_url(url):
#     if url.endswith('/'):
#         return url
#     else:
#         parts = url.split('/')
#         # Remove the last part
#         parts.pop()
#         # Reconstruct the URL
#         modified_url = '/'.join(parts)
#         return modified_url
  
# Helper functions
def is_valid_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in ('http', 'https') and not url.startswith('data:')

def sanitize_filename(url, ext, max_length=255):
    parsed_url = urlparse(url)
    url_hash = hashlib.md5(url.encode()).hexdigest()
    if ext == 'css':
        extension = '.css'
    elif ext == 'js':
        extension = '.js'

    elif ext == 'html':
        extension = os.path.splitext(parsed_url.path)[1]
        if not extension:
            extension = '.html'
    elif ext == 'img':
        extension = os.path.splitext(parsed_url.path)[1]
        if not extension:
            extension = '.png'
    else:
        extension = os.path.splitext(parsed_url.path)[1]
    filename = f"{url_hash}{extension}"
    print("url = "+str(parsed_url))
    print("filename = "+filename)
    return filename[:max_length]

def download_resource(url, save_dir, filename, retries=3, delay=5):
    os.makedirs(save_dir, exist_ok=True)
    filepath = os.path.join(save_dir, filename)
    attempt = 0
    while attempt < retries:
        try:
            with requests.Session() as session:
                session.verify = False  # Disable SSL verification
                response = session.get(url, stream=True, timeout=10)
                with open(filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)
                response.close()
            logging.info(f"Successfully downloaded {url} to {filepath}")
            break  # Exit the loop if the download is successful
        except (SSLError, ConnectionError, Timeout) as e:
            attempt += 1
            if attempt >= retries:
                logging.error(f"Failed to download {url} after {retries} attempts. Error: {e}")
            else:
                logging.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay} seconds...")
                time.sleep(delay)
        finally:
            if 'response' in locals() and response is not None:
                response.close()

def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
    result = chardet.detect(raw_data)
    return result['encoding']

def read_file_with_fallbacks(file_path):
    encodings = [detect_encoding(file_path), 'utf-8', 'latin-1']
    for encoding in encodings:
        if encoding is None:
            continue
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, TypeError):
            continue
    raise UnicodeDecodeError(f"Unable to decode file {file_path} with available encodings.")


def update_html(html_file, resource_dir, new_cleaned_url):
    print(f"Updating HTML file: {html_file}")
    if not os.path.isfile(html_file):
        print(f"File not found: {html_file}")
        return

    try:
        html_content = read_file_with_fallbacks(html_file)
    except UnicodeDecodeError as e:
        print(e)
        return

    print("Parsing HTML content...")
    soup = BeautifulSoup(html_content, 'html.parser')
    
    def process_attributes():
        print("Processing all attributes for all tags...")
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if tag.name in ['img', 'script', 'link', 'iframe'] and attr in ['src', 'href']:
                    if isinstance(value, str):
                        if value.startswith('http') or value.startswith('https'):
                            continue
                        elif value.startswith('/'):
                            tag[attr] = urljoin(new_cleaned_url, value)
                        else:
                            tag[attr] = url + '/' + value
                else:
                    if isinstance(value, str) and value.startswith('/'):
                        tag[attr] = urljoin(new_cleaned_url, value)

    def remove_base_tag():
        nonlocal soup
        base_tag = soup.find('base')
        if base_tag:
            print("Removing base tag...")
            base_tag.decompose()

    def process_link_tag(tag):
        href = tag.get('href')

        if tag.name == 'link':
            if tag.get('rel') == ['stylesheet'] or tag.get('as') == 'style':
                if href and is_valid_url(href):
                    css_url = urljoin(html_file, href)
                    css_filename = sanitize_filename(href, 'css')  # First call to sanitize_filename
                    local_path = os.path.join('local_resources', 'css', css_filename)
                    tag['href'] = local_path
                    download_resource(css_url, os.path.join(resource_dir, 'css'), css_filename)
            elif tag.get('rel') == ['manifest']:
                if href and is_valid_url(href):
                    manifest_url = urljoin(html_file, href)
                    manifest_filename = sanitize_filename(href, 'css')
                    tag['href'] = os.path.join('local_resources', 'css', manifest_filename)
                    download_resource(manifest_url, os.path.join(resource_dir, 'css'), manifest_filename)
            elif tag.get('rel') == ['icon']:
                if href and is_valid_url(href):
                    icon_url = urljoin(html_file, href)
                    icon_filename = sanitize_filename(href, 'img')
                    local_path = os.path.join('local_resources', 'img', icon_filename)
                    tag['href'] = local_path
                    download_resource(icon_url, os.path.join(resource_dir, 'img'), icon_filename)

            elif tag.get('as') =='script':
                    if href and is_valid_url(href):
                        icon_url = urljoin(html_file, href)
                        icon_filename = sanitize_filename(href, 'js')
                        local_path = os.path.join('local_resources', 'js', icon_filename)
                        tag['href'] = local_path
                        download_resource(icon_url, os.path.join(resource_dir, 'js'), icon_filename)

    def process_script_tag(tag):
        src = tag.get('src')
        if src and is_valid_url(src):
            js_url = urljoin(html_file, src)
            js_filename = sanitize_filename(src, 'js')
            local_path = os.path.join('local_resources', 'js', js_filename)
            tag['src'] = local_path
            download_resource(js_url, os.path.join(resource_dir, 'js'), js_filename)

    def process_iframe_tag(tag):
        src = tag.get('src')
        if src and is_valid_url(src):
            iframe_url = urljoin(html_file, src)
            iframe_filename = sanitize_filename(src, ' ')
            local_path = os.path.join('local_resources', 'iframes', iframe_filename)
            tag['src'] = local_path
            download_resource(iframe_url, os.path.join(resource_dir, 'iframes'), iframe_filename)

    def process_img_tag(tag):
        src = tag.get('src')
        if src and is_valid_url(src):
            img_url = urljoin(html_file, src)
            img_filename = sanitize_filename(src, 'img')
            local_path = os.path.join('local_resources', 'img', img_filename)
            tag['src'] = local_path
            download_resource(img_url, os.path.join(resource_dir, 'img'), img_filename)
        data_src = tag.get('data-src')
        if data_src and is_valid_url(data_src):
            data_img_url = urljoin(html_file, data_src)
            data_img_filename = sanitize_filename(data_src, 'img')
            local_path = os.path.join('local_resources', 'img', data_img_filename)
            tag['data-src'] = local_path
            tag['src'] = local_path
            download_resource(data_img_url, os.path.join(resource_dir, 'img'), data_img_filename)
        if tag.has_attr('srcset'):
            del tag['srcset']


    def process_remaining_tags():
        print(f"Processing other tags...")

        for meta_tag in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
            meta_tag.decompose()
        for tag in soup.find_all():
            # Check if tag is one of the specified tags
            if tag.name in ['a', 'script', 'link', 'iframe', 'img', 'meta', 'form']:
                continue
            
            # Check all attributes of the tag for URLs
            for attr, value in list(tag.attrs.items()):
                if isinstance(value, str) and value.startswith(('http', 'https')):
                    # Unwrap the link
                    tag.unwrap()
                    break

    def remove_source_tags():
        print("Removing source tags")
        for s in soup.select('source'):
            s.extract()

    def remove_noscript_tags():
        print("Removing noscript tags...")
        for tag in soup.find_all('noscript'):
            tag.unwrap()

    process_attributes()
    remove_base_tag()

    # Create and start a thread for each link tag
    link_tags = soup.find_all('link')
    print(f"Starting threads for {len(link_tags)} link tags...")
    link_threads = [threading.Thread(target=process_link_tag, args=(tag,)) for tag in link_tags]
    for thread in link_threads:
        thread.start()

    # Create and start a thread for each script tag
    script_tags = soup.find_all('script')
    print(f"Starting threads for {len(script_tags)} script tags...")
    script_threads = [threading.Thread(target=process_script_tag, args=(tag,)) for tag in script_tags]
    for thread in script_threads:
        thread.start()

    # Create and start a thread for each iframe tag
    iframe_tags = soup.find_all('iframe')
    print(f"Starting threads for {len(iframe_tags)} iframe tags...")
    iframe_threads = [threading.Thread(target=process_iframe_tag, args=(tag,)) for tag in iframe_tags]
    for thread in iframe_threads:
        thread.start()

    # Create and start a thread for each img tag
    img_tags = soup.find_all('img')
    print(f"Starting threads for {len(img_tags)} img tags...")
    img_threads = [threading.Thread(target=process_img_tag, args=(tag,)) for tag in img_tags]
    for thread in img_threads:
        thread.start()

    print("Starting threads for removing noscript tags...")
    noscript_thread = threading.Thread(target=remove_noscript_tags)
    noscript_thread.start()

    print("Starting threads for removing source tags...")
    source_thread = threading.Thread(target=remove_source_tags)
    source_thread.start()

    # Wait for all threads to complete
    all_threads = link_threads + script_threads + iframe_threads + img_threads + [noscript_thread, source_thread]
    print("Waiting for all threads to complete...")
    for thread in all_threads:
        thread.join()

    process_remaining_tags()

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(str(soup))
    print("Update completed.")

def clean_url(url):
    parsed_url = urlparse(url)
    
    # Remove :443 if it is present in the netloc
    netloc = parsed_url.netloc
    if netloc.endswith(':443'):
        netloc = netloc[:-4]  # Remove the :443 part
    
    # Reconstruct the URL with only the path component
    cleaned_url = urlunparse((parsed_url.scheme, netloc, parsed_url.path, '', '', ''))
    
    return cleaned_url



def url_screenshot(url, filename):
    options = webdriver.ChromeOptions()
    options.add_argument('headless')
    options.add_argument('--window-size=1920,1080')  # Set a larger window size
    driver = webdriver.Chrome(options=options)
    
    try:
        driver.set_page_load_timeout(15)
        
        try:
            # Open the URL
            driver.get(url)
            
            # Allow some time for the page to load
            time.sleep(15)  # Wait for 10 seconds

        except TimeoutException:
            print(f"Page load timed out for {url}. Stopping further loading.")
            driver.execute_script("window.stop();")
        
        # Scroll to capture the full height of the webpage
        total_height = driver.execute_script("return document.body.scrollHeight")
        driver.set_window_size(1920, total_height)  # Set window size to capture the full height
        driver.execute_script("window.scrollTo(0, 0);")  # Scroll to the top of the page
        
        try:
            driver.save_screenshot(filename)
            print(f"Screenshot saved for {url} as {filename}")
        except Exception as e:
            print(f"An error occurred while capturing screenshot for {url}: {e}")

    finally:
        driver.quit()
    

def compare_images(image1, image2):
    # Read images
    img1 = cv2.imread(image1)
    img2 = cv2.imread(image2)

    # Resize images to the same dimensions
    width = min(img1.shape[1], img2.shape[1])
    height = min(img1.shape[0], img2.shape[0])
    img1 = cv2.resize(img1, (width, height))
    img2 = cv2.resize(img2, (width, height))

    # Convert images to grayscale
    gray_img1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
    gray_img2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)

    # Compute SSIM (Structural Similarity Index)
    ssim_index = ssim(gray_img1, gray_img2)

    # Compute histogram correlation
    hist_corr = cv2.compareHist(cv2.calcHist([gray_img1],[0],None,[256],[0,256]),
                                cv2.calcHist([gray_img2],[0],None,[256],[0,256]),
                                cv2.HISTCMP_CORREL)

    return ssim_index, hist_corr



def extract_legitimate_urls():
    if os.path.exists('urls.txt'):
        return
    file_path = 'top30000urls.csv'
    # Read the CSV file
    with open(file_path, 'r') as csv_file:
        reader = csv.DictReader(csv_file)
        urls = [row["Domain"] for row in reader]
    with open('urls.txt','w') as file:
        for url in urls:
            file.write(url+'\n')

    print('Legitimiate Urls Extracted')

def extract_phishing_urls():
    if os.path.exists('urls.txt'):
        return
    input_file_path = 'phishing_urls.csv'
    output_file_path = 'urls.txt'

    # Read the CSV file and extract URLs
    urls = []
    with open(input_file_path, 'r') as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            url = row[0]+'/'
            # Remove http:// and https:// prefixes
            if url.startswith("http://"):
                url = url[len("http://"):]
            elif url.startswith("https://"):
                url = url[len("https://"):]
            urls.append(url)

    # Write the URLs to the output text file
    with open(output_file_path, 'w') as output_file:
        for url in urls:
            output_file.write(url + '\n')

    print(f"Extracted and cleaned URLs have been saved to {output_file_path}")



# Main part of the script

print("-----------------------WEB RESOURCES DOWNLOADER---------------------------------")
ch = input("Enter 1 to download legitimate sources and 2 for downloading phishing sources ")

if ch == "1":
    extract_legitimate_urls()

elif ch == "2":
    extract_phishing_urls()

else:
    print('Wrong choice..Exiting......')
    exit


csv_file = "info.csv"
if os.path.exists(csv_file):
    print("csv file already exists")
else:
    print("creating csv file")
    headers = ['Index','URL','HTML Folder']
    with open(csv_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        
        # Writing the header
        csvwriter.writerow(headers)
        

resources_base_dir = 'legitimate_resources_testing_features'
with open('urls.txt', 'r', encoding='utf-8') as f:
    count = 0
    for i, line in enumerate(f):
        count+=1
        try:
            start_time = time.time()
            url = "https://" + line
            new_cleaned_url = clean_url(url)
            cleaned_url = new_cleaned_url[8:]
            # folder = modify_url(cleaned_url)
            folder = cleaned_url
            domain = tldextract.extract(cleaned_url).domain
            outer_folder = os.path.join(resources_base_dir, str(count)+'_'+str(domain))
            print(cleaned_url+" -> "+folder)
            # Run wget command
            user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3', 
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        # Add more user agents as needed
    ]
            
            user_agent = random.choice(user_agents)

            command = [
                'wget',
                '--mirror',
                '--convert-links',
                '--adjust-extension',
                '--page-requisites',
                '--no-parent',
                '-U',
                user_agent,
                '--timeout=10',
                '-o', 'log.txt',
                '-P', outer_folder,
                new_cleaned_url
            ]

            # Prefix the wget command with `timeout 30`
            full_command = ['timeout', '10'] + command

            result = subprocess.run(full_command, text=True, capture_output=True)

            logging.info(result)
            full_folder = os.path.join(outer_folder, folder)

            
            # print("In else case")
            is_index = False
            for filename in os.listdir(full_folder):
                # print("finding if there is index.html")
                # Check if it's a file (not a directory) before printing
                if os.path.isfile(os.path.join(full_folder, filename)):
                #   print(filename)
                    if(filename == "index.html"):
                        index_html = 'index.html'
                        is_index = True
                        break
                    
            if is_index == False:
                for filename in os.listdir(full_folder):
                    # print("finding if there is a html file")
                # Check if it's a file (not a directory) before printing
                    if os.path.isfile(os.path.join(full_folder, filename)):
                        if(filename[-4:]=='html'):
                            index_html = filename
                            is_index = True
                            break
                
                else:
                    count-= 1
                    shutil.rmtree(outer_folder, ignore_errors=True)
                    continue

            index_html = 'index.html'
            print("HTML FILE = "+index_html)
            
            # Adjust the path based on your directory structure
            html_file = os.path.join(outer_folder, folder,index_html)
            # resource_dir = os.path.join(outer_folder, 'local_resources')
            resource_dir = os.path.join(outer_folder,folder, 'local_resources')

            # change outer_folder to folder

            update_html(html_file, resource_dir,new_cleaned_url)
            d_time = time.time()

            screenshots = os.path.join(resource_dir,'screenshots')
            os.makedirs(screenshots, exist_ok=True)
            online = os.path.join(screenshots,'online.png')
            offline = os.path.join(screenshots,'offline.png')
            
            path_wanted = "file://"+os.path.abspath(html_file)
            print("absolute path = "+ path_wanted)

            images = [
        threading.Thread(target=url_screenshot, args=(new_cleaned_url,online)),
        threading.Thread(target=url_screenshot, args=(path_wanted,offline)),
        ]
            
            print("Starting image parallel tasks...")
            for task in images:
                task.start()

            # Wait for all threads to complete
            print("Waiting for image tasks to complete...")
            for task in images:
                task.join()

            if not os.path.exists(online) or not os.path.exists(offline):
                # Delete the outer folder
                logging.warning(f"One of {online} or {offline} is missing. Deleting {outer_folder}...")
                count-= 1
                shutil.rmtree(outer_folder, ignore_errors=True)
                continue
    
            ss_end = time.time()
            ssim_index, hist_corr = compare_images(online,offline)

            print(f"SSIM Index: {ssim_index}")
            print(f"Histogram Correlation: {hist_corr}")
            # Can change the boundary to 0.8 also.
            if hist_corr < 0.9:
                logging.warning(f"Histogram correlation {hist_corr} is less than 0.9. Deleting {outer_folder}...")
                count-= 1
                shutil.rmtree(outer_folder, ignore_errors=True)
                continue

            with open('image_comparision.txt','a') as file:
                file.write(str(cleaned_url)+"\tSSIM Index = "+str(ssim_index)+"\tHistogram Correlation = "+str(hist_corr)+"\n")

            end_time = time.time()
            execution_time = end_time - start_time
            # print("Execution time:", execution_time, "seconds")
            with open('time_taken.txt','a') as time_file:
                ss = ss_end - d_time
                download = d_time - start_time
                compare = end_time - ss_end
                total_time = end_time - start_time
                time_file.write(str(cleaned_url)+" download time = "+str(download)+" screenshot time = "+str(ss)+" screenshot compare time = "+str(compare)+" Total Time = "+str(total_time)+"\n")
                time_file.close()

            # Updating info.csv:
            info_arr = [count,cleaned_url,html_file]
            with open('info.csv', 'a', newline='') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(info_arr)

        except Exception as e:
            logging.error(f"An error occurred with URL {line.strip()}: {e}")
            # print(f"An error occurred with URL {line.strip()}: {e}")
            continue  # Skip to the next URL
