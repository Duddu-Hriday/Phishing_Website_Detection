# Updates in the code
## Downloading HTML page:
### Using wget
  ```
  wget --mirror --convert-links --adjust-extension --page-requisites --no-parent -U Mozilla/5.0 --timeout=30 -o log.txt 'url'
  ```

## Downloading images, javascript, CSS:
* Using Requests Library in Python
* Update: Download iframes and other links

## Taking a screenshot of the webpage:
* Online webpage and the Locally Downloaded webpage
* Using Selenium,Pillow

## Comparing the Similarity of the screenshots (offline and online):
* Using SSIM Index and Histogram Co-relation **Using `skimage` library**

## Update 10th June 2024
* Added Threading to the Code
    - Parllelized the downloading of the resources
    - Parallelized the screenshot taking of online webpage and offline webpage
    - Parallelized the screenshot function.
## Update : Extracting working and scrapable urls using wget and requests
- working_urls_extractor.py
- wget_checker.py

## Update: Added Features to feature_extraction.py
- pre_at_urls
- is_link_valid
- multiple_https_check
- form_empty_action
- same_form_action_domain
- is_mail
- num_of_redirects
- has_window_status
- status_bar_customization
- https_in_domain
- abnormal_url
- is_at_symbol_present
- targeted_domain
## Update: Extracting phishing urls from phishtank

