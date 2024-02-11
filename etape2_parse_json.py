import json
import os

# This function scans a directory for JSON files, parses them to find specific keywords within
# the x_mitre_platforms attribute of each 'attack-pattern' object, and compiles the matching
# external IDs along with the filenames and matched keywords into a list.
def extract_info_and_compile_ids(directory, keywords):
    results = []  # Initialize an empty list to store results

    # Iterate through each file in the specified directory
    for filename in os.listdir(directory):
        if filename.endswith(".json"):  # Check if the file is a JSON file
            file_path = os.path.join(directory, filename)  # Construct the full file path
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)  # Load the JSON content

                    # Loop through each object in the 'objects' array of the JSON file
                    for obj in data.get('objects', []):
                        # Filter for 'attack-pattern' objects
                        if obj.get('type') == 'attack-pattern':
                            platforms = obj.get('x_mitre_platforms', [])  # Get platforms

                            # Find keywords that match any of the platforms listed in the object
                            matched_keywords = [kw for kw in keywords if any(kw in platform for platform in platforms)]
                            if matched_keywords:
                                # Look for the 'external_id' within 'external_references'
                                for ref in obj.get('external_references', []):
                                    if 'external_id' in ref:
                                        # Compile the results
                                        results.append({
                                            "filename": filename,
                                            "matched_keywords": matched_keywords,
                                            "external_id": ref['external_id']
                                        })
                                        break  # Stop after the first match
            except Exception as e:
                print(f"Error processing {filename}: {e}")

    # Save the compiled results to a new JSON file
    with open('external_ids_details.json', 'w', encoding='utf-8') as outfile:
        json.dump(results, outfile, indent=4)

# Path to the directory containing JSON files
directory_path = 'json'  # Adjust as needed

# List of keywords to search within x_mitre_platforms
keywords = ["Office 365", "Azure AD", "Google Workspace", "SaaS", "IaaS"]

# Execute the function
extract_info_and_compile_ids(directory_path, keywords)
