import json
import re

def load_external_ids_details(file_path):
    """
    Load external ID details from a specified JSON file.
    
    :param file_path: Path to the JSON file containing external IDs details.
    :return: A list of dictionaries containing external IDs details.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error: File {file_path} contains invalid JSON.")
        return []

def modify_entry_kill_chain(entry, external_ids):
    """
    Modify the kill_chain values for entries that match the specified external IDs.
    
    :param entry: A dictionary representing a single entry in the MITRE attack pattern dataset.
    :param external_ids: A set of external IDs to match against.
    :return: A tuple (bool, list) where bool indicates if modifications were made, and list is the original kill_chain if modified.
    """
    external_id = entry.get('meta', {}).get('external_id')
    if external_id in external_ids:
        # Make a copy of the original kill_chain before modification
        original_kill_chain = entry.get('meta', {}).get('kill_chain', []).copy()
        entry['meta']['kill_chain'] = [
            re.sub(r'mitre-(attack|pre-attack|mobile-attack)', r'mitre-cloud-attack', kc) 
            for kc in entry.get('meta', {}).get('kill_chain', [])
        ]
        return True, original_kill_chain
    return False, []

# Load external IDs details
external_ids_details = load_external_ids_details('external_ids_details.json')
if not external_ids_details:
    # Exit if the external IDs details could not be loaded
    exit()

external_ids = {detail['external_id'] for detail in external_ids_details}

# Attempt to load the original MITRE attack pattern JSON
try:
    with open('mitre-attack-pattern.json', 'r', encoding='utf-8') as file:
        data = json.load(file)
except Exception as e:
    print(f"Failed to load MITRE attack pattern JSON: {e}")
    exit()

# Process and modify entries as needed
modified_entries = []
for entry in data['values']:
    modified, original_kill_chain = modify_entry_kill_chain(entry, external_ids)
    if modified:
        modified_entries.append({
            'filename': entry.get('uuid'),
            'original_kill_chain': original_kill_chain,
            'suggested_kill_chain': entry.get('meta', {}).get('kill_chain', [])
        })

# Save the modified dataset and a list of modified entries
try:
    with open('new_mitre_attack_pattern.json', 'w', encoding='utf-8') as new_file:
        json.dump(data, new_file, indent=4)
    with open('modified_entries.json', 'w', encoding='utf-8') as modified_file:
        json.dump(modified_entries, modified_file, indent=4)
    print("Data saved successfully.")
except Exception as e:
    print(f"Failed to save modified data: {e}")
