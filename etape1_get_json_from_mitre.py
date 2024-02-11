import requests
import os
from concurrent.futures import ThreadPoolExecutor
import argparse

# Parse command line arguments for number of threads and error handling
parser = argparse.ArgumentParser(description='Download JSON files from GitHub with multithreading.')
parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads to use for downloading.')
args = parser.parse_args()

downloaded_urls = set()  # Keep track of downloaded URLs to avoid duplicates
downloaded_files_count = 0  # Counter for downloaded files

def download_file(file_info, local_path):
    global downloaded_files_count
    download_url, local_file_path = file_info
    try:
        if download_url not in downloaded_urls:
            # Attempt to download the file
            response = requests.get(download_url)
            if response.status_code == 200:
                with open(local_file_path, 'wb') as f:
                    f.write(response.content)
                print(f"Downloaded {os.path.basename(local_file_path)}")
                downloaded_urls.add(download_url)  # Mark this URL as downloaded
                downloaded_files_count += 1  # Increment the counter
            else:
                print(f"Failed to download {download_url}: HTTP {response.status_code}")
        else:
            print(f"URL {download_url} already processed, skipping.")
    except Exception as e:
        print(f"Error downloading {download_url}: {e}")

def download_files_from_github(folder_url, local_path):
    api_url = f"https://api.github.com/repos/mitre/cti/contents/{folder_url}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            files = response.json()
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                for file in files:
                    if file['type'] == 'file' and file['name'].endswith('.json'):
                        local_file_path = os.path.join(local_path, file['name'])
                        download_url = file['download_url']
                        executor.submit(download_file, (download_url, local_file_path), local_path)
        else:
            print(f"Failed to retrieve files list from {folder_url}: HTTP {response.status_code}")
    except Exception as e:
        print(f"Error accessing {api_url}: {e}")

if __name__ == "__main__":
    local_path = "./json"
    os.makedirs(local_path, exist_ok=True)  # Ensure the local directory exists

    folder_urls = [
        "enterprise-attack/attack-pattern",
        "ics-attack/attack-pattern",
        "mobile-attack/attack-pattern",
        "pre-attack/attack-pattern",
        "capec/2.1/attack-pattern"
    ]

    # Start downloading files from each specified GitHub folder
    for url in folder_urls:
        download_files_from_github(url, local_path)

    print(f"Finished downloading JSON files. Total files downloaded: {downloaded_files_count}")
