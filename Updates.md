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
* Code taken from Shahil Patel's Git Repo:
```
https://github.com/ShahilPatel-IITDh/Deep-Learning-Phishy-Classification/blob/main/MainAlgorithm/screenshotCapture.py
```

## Comparing the Similarity of the screenshots (offline and online):
* Using SSIM Index and Histogram Co-relation **Using `skimage` library**

## Update 10th June 2024
* Added Threading to the Code
    - Parllelized the downloading of the resources
    - Parallelized the screenshot taking of online webpage and offline webpage
    - Parallelized the screenshot function.
