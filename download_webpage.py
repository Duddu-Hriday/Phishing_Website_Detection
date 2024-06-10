'''
    Code written by Duddu Hriday, 4th Year student at IIT Dharwad
    This code is a part of a project on Phishing website detection with Professor Tamal Das and Aditya Kulkarni
    This code does the following things:
    - Download webpage using wget
    - Download required resources like css, js, images, other files using requests Library
    - Change the path pointed to the server in the html file to the local path to load them even when offline
'''

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

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from PIL import Image
import time
from selenium.common.exceptions import WebDriverException
import io

import cv2
from skimage.metrics import structural_similarity as ssim

import threading

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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


def update_html(html_file, resource_dir):
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
    base_tag = soup.find('base')
    base_url = None
    if base_tag and base_tag.get('href'):
        base_url = base_tag['href']

    def process_tags(tags):
        print(f"Processing {len(tags)} tags...")
        for tag in tags:
            href = tag.get('href')
            src = tag.get('src')
            data_src = tag.get('data-src')
            as_attr = tag.get('as')

            if base_url:
                if href and not href.startswith(('http://', 'https://', '//')):
                    tag['href'] = urljoin(base_url, href)
                if src and not src.startswith(('http://', 'https://', '//')):
                    tag['src'] = urljoin(base_url, src)
                if data_src and not data_src.startswith(('http://', 'https://', '//')):
                    tag['data-src'] = urljoin(base_url, data_src)

    def remove_base_tag():
        nonlocal soup
        if base_tag:
            print("Removing base tag...")
            base_tag.decompose()

    def process_link_tags(tags):
        print(f"Processing {len(tags)} link tags...")
        for tag in tags:
            href = tag.get('href')
            src = tag.get('src')
            data_src = tag.get('data-src')
            as_attr = tag.get('as')

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
                else:
                    if href and is_valid_url(href):
                        script_url = urljoin(html_file, href)
                        script_filename = sanitize_filename(href, 'html')
                        local_path = os.path.join('local_resources', 'otherlinks', script_filename)
                        tag['href'] = local_path
                        download_resource(script_url, os.path.join(resource_dir, 'otherlinks'), script_filename)

    def process_script_tags(tags):
        print(f"Processing {len(tags)} script tags...")
        for tag in tags:
            src = tag.get('src')
            if src and is_valid_url(src):
                js_url = urljoin(html_file, src)
                js_filename = sanitize_filename(src, 'js')
                local_path = os.path.join('local_resources', 'js', js_filename)
                tag['src'] = local_path
                download_resource(js_url, os.path.join(resource_dir, 'js'), js_filename)

    def process_iframe_tags(tags):
        print(f"Processing {len(tags)} iframe tags...")
        for tag in tags:
            src = tag.get('src')
            if src and is_valid_url(src):
                iframe_url = urljoin(html_file, src)
                iframe_filename = sanitize_filename(src, ' ')
                local_path = os.path.join('local_resources', 'iframes', iframe_filename)
                tag['src'] = local_path
                download_resource(iframe_url, os.path.join(resource_dir, 'iframes'), iframe_filename)

    def process_img_tags(tags):
        print(f"Processing {len(tags)} img tags...")
        for tag in tags:
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

    def remove_noscript_tags():
        print("Removing noscript tags...")
        for tag in soup.find_all('noscript'):
            tag.unwrap()

    # Process tags and remove base tag synchronously
    process_tags(soup.find_all(['link', 'script', 'img', 'iframe','a','meta']))
    remove_base_tag()

    # Define parallel tasks for remaining operations
    tasks = [
        threading.Thread(target=process_link_tags, args=(soup.find_all('link'),)),
        threading.Thread(target=process_script_tags, args=(soup.find_all('script'),)),
        threading.Thread(target=process_iframe_tags, args=(soup.find_all('iframe'),)),
        threading.Thread(target=process_img_tags, args=(soup.find_all('img'),)),
        threading.Thread(target=remove_noscript_tags)
    ]

    # Start parallel tasks
    print("Starting parallel tasks...")
    for task in tasks:
        task.start()

    # Wait for all threads to complete
    print("Waiting for tasks to complete...")
    for task in tasks:
        task.join()

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


def capture_full_page_screenshot(url, screenshotFile, driver_path='/usr/bin/chromedriver'):
    print("url = " + url)
    print("screenshot = " + screenshotFile)
    chrome_options = Options()
    # Set up Chrome options for headless mode
    chrome_options.add_argument('--headless')
    # Disable the GPU 
    chrome_options.add_argument("--disable-gpu")
    # Disable the sandbox
    chrome_options.add_argument("--no-sandbox")
    # Disable the DevShmUsage
    chrome_options.add_argument("--disable-dev-shm-usage")
    
    # Initialize the ChromeDriver service
    service = Service(driver_path)
    
    # Initialize the web driver with Chrome options
    driver = webdriver.Chrome(service=service, options=chrome_options)

    print("--code entered the screenshot capture function")
    print("|")

    try:
        driver.get(url)

        time.sleep(8)

        # Handle WebDriverException (e.g., net::ERR_NAME_NOT_RESOLVED)
        if "ERR_NAME_NOT_RESOLVED" in driver.page_source:
            print(f"Error: {url} could not be resolved. Skipping...")
            return
        
        # Get the page height
        page_height = driver.execute_script("return document.body.scrollHeight")

        # Set the initial viewport height
        viewport_height = driver.execute_script("return window.innerHeight")

        # Function to capture screenshot for a portion of the page
        def capture_screenshot(start, result_list):
            driver.execute_script(f"window.scrollTo(0, {start});")
            time.sleep(2)  # Adjust sleep time as needed
            screenshot = driver.get_screenshot_as_png()
            result_list.append(Image.open(io.BytesIO(screenshot)))

        # Number of threads
        # num_threads = page_height // viewport_height + 1
        threads = []
        results = []

        # Capture screenshots using threads
        for i in range(0, page_height, viewport_height):
            result_list = results  # Shared list for storing thread results
            thread = threading.Thread(target=capture_screenshot, args=(i, result_list))
            threads.append(thread)
            thread.start()

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        # Stitch the screenshots vertically
        full_page_screenshot = Image.new("RGB", (driver.execute_script("return window.innerWidth"), page_height))
        y_offset = 0

        for screenshot in results:
            full_page_screenshot.paste(screenshot, (0, y_offset))
            y_offset += screenshot.height

        # Save the full-page screenshot
        full_page_screenshot.save(screenshotFile)

    except WebDriverException as e:
        # Log the WebDriverException
        logging.error(f"WebDriverException while processing URL: {url}. Error: {str(e)}")
    except Exception as e:
        # Log other exceptions
        logging.error(f"Exception while processing URL: {url}. Error: {str(e)}")

    finally:
        driver.quit()

    print("|")
    print("--Code exited the screenshot capture function\n")


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
# def compare_images(image1, image2):
#     # Read images
#     img1 = cv2.imread(image1)
#     img2 = cv2.imread(image2)

#     # Convert images to grayscale
#     gray_img1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
#     gray_img2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)

#     # Compute SSIM (Structural Similarity Index)
#     ssim_index = ssim(gray_img1, gray_img2)

#     # Compute histogram correlation
#     hist_corr = cv2.compareHist(cv2.calcHist([gray_img1],[0],None,[256],[0,256]),
#                                 cv2.calcHist([gray_img2],[0],None,[256],[0,256]),
#                                 cv2.HISTCMP_CORREL)

#     return ssim_index, hist_corr

# Main part of the script


resources_base_dir = 'download_websites'
max_wait_time = 300
with open('urls.txt', 'r', encoding='utf-8') as f:
    count = 0
    for i, line in enumerate(f):
        count+=1
        try:
            start_time = time.time()
            # folder = line.strip()
            # line = "https://"+line
            # url = line.strip()
            # # newurl = "https://"+url
            # cleaned_url = clean_url(url)
            # new_cleaned_url = "https://" + cleaned_url
            # new_cleaned_url = clean_url(newurl)
            url = "https://" + line
            new_cleaned_url = clean_url(url)
            cleaned_url = new_cleaned_url[8:]
            folder = cleaned_url
            domain = tldextract.extract(cleaned_url).domain
            outer_folder = os.path.join(resources_base_dir, f"{count}_{domain}")
            html_extract = cleaned_url.split('/')[-1]
            if(html_extract[-4:]=='html'):
                new_folder = folder.split('/')
                folder = folder.replace(new_folder[-1],"")
                index_html = html_extract
            else:
                index_html = 'index.html'

            # Run wget command
            command = [
                'wget',
                '--mirror',
                '--convert-links',
                '--adjust-extension',
                '--page-requisites',
                '--no-parent',
                '-U',
                'Mozilla/5.0',
                '--timeout=30',
                '-o', 'log.txt',
                '-P', outer_folder,
                new_cleaned_url
            ]

            # Prefix the wget command with `timeout 30`
            full_command = ['timeout', '30'] + command

            result = subprocess.run(full_command, text=True, capture_output=True)

            # Print the stdout and stderr to the command prompt
            # print(result)
            logging.info(result)
            # print(result.stderr)

            # Adjust the path based on your directory structure
            html_file = os.path.join(outer_folder, folder,index_html)
            # resource_dir = os.path.join(outer_folder, 'local_resources')
            resource_dir = os.path.join(outer_folder,folder, 'local_resources')

            # change outer_folder to folder

            update_html(html_file, resource_dir)

            screenshots = os.path.join(resource_dir,'screenshots')
            os.makedirs(screenshots, exist_ok=True)
            online = os.path.join(screenshots,'online.png')
            offline = os.path.join(screenshots,'offline.png')
            # print("cleaned_url = "+cleaned_url)
            # print("html_file= "+html_file)
            # # url,file,driver
            print("absolute path = "+os.path.abspath(html_file))
            capture_full_page_screenshot(new_cleaned_url,online)
            path_wanted = "file://"+os.path.abspath(html_file)
            capture_full_page_screenshot(path_wanted,offline)

            images = [
        threading.Thread(target=capture_full_page_screenshot, args=([new_cleaned_url,online],)),
        threading.Thread(target=capture_full_page_screenshot, args=([path_wanted,offline],)),
        ]
            
            print("Starting image parallel tasks...")
            for task in images:
                task.start()

            # Wait for all threads to complete
            print("Waiting for image tasks to complete...")
            for task in images:
                task.join()

            

            ssim_index, hist_corr = compare_images(online,offline)

            print(f"SSIM Index: {ssim_index}")
            print(f"Histogram Correlation: {hist_corr}")

            with open('image_comparsion.txt','a') as file:
                file.write(str(cleaned_url)+"\tSSIM Index = "+str(ssim_index)+"\tHistogram Correlation = "+str(hist_corr)+"\n")

            end_time = time.time()
            execution_time = end_time - start_time
            # print("Execution time:", execution_time, "seconds")
            with open('time.txt','a') as time_file:
                time_file.write(str(cleaned_url)+" "+str(execution_time)+" -> Using More Threading"+"\n")
                time_file.close()

        except Exception as e:
            logging.error(f"An error occurred with URL {line.strip()}: {e}")
            # print(f"An error occurred with URL {line.strip()}: {e}")
            continue  # Skip to the next URL
