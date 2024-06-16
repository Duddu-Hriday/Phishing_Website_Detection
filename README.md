# OFFLINE WEBPAGE DOWNLOADER
## Requirements:
- Python 3
  * Selenium 4
  * Requests Library
  * Beautifulsoup
  * urlparse
- Wget

## Python 3 installation:
```
https://www.python.org/downloads/
```

## pip Installation:
```
sudo apt install python3-pip
```

## wget Installation
```
sudo apt install wget
```

## Required Python Libraries and Frameworks Installtion
```
pip install beautifulsoup4 requests urllib3 tldextract chardet selenium webdriver_manager Pillow opencv-python scikit-image
```

## Instructions:
- Clone the project into Local Directory
- Make sure that download_webpage.py and urls.txt are in the same direcotory
- On running code a new directory by the name legitimate_resources is created.
- A folder by the name local_resources is created in legitimate_resources directory.
- This local_resources folder contains seperate folders for css,js,images and other files.
- It also forms a folder by the name screenshots, which stores the picture of the locally loaded webpage and the original webpage to calculate the similarity of the local webpage with original one.
- The similarity calculations are shown in a file named image_comparision.txt

## Command to clone the project:
```
git clone https://github.com/Duddu-Hriday/offline-website-downloader.git
```

## Run the Code:
```
python3 download_webpage.py
```
