
# MISP Project: MITRE Cloud Attack Matrix Extension

## Description
This project extends the existing matrix in the MISP (Malware Information Sharing Platform) framework by adding a new column specifically for cloud-related attack patterns. The new column, named "mitre-cloud-attack", incorporates data derived from the existing columns: "mitre-attack", "mitre-pre-attack", and "mitre-mobile-attack". By parsing JSON files provided by MITRE, the project identifies and segregates cloud-related attack patterns into this new column, enhancing the comprehensiveness and relevance of threat intelligence for cloud environments.

## Requirements
- Python 3.x
- Requests library (for fetching JSON data from MITRE)
- Any other dependencies required by the provided scripts

To install the necessary Python libraries, you can use the following command:

```sh
pip install requests
```

Ensure you have Python and pip installed on your system before running the command.

## Usage
The project is structured into three main stages, each corresponding to a script that needs to be executed sequentially to achieve the desired outcome.

### Step 1: Fetch JSON Data from MITRE
The first step involves fetching relevant JSON data from MITRE's repositories. This is done using the `etape1_get_json_from_mitre.py` script.

```sh
python etape1_get_json_from_mitre.py
```

This script downloads JSON files containing information about attack patterns from the MITRE ATT&CK, PRE-ATT&CK, and Mobile ATT&CK matrices.

### Step 2: Parse JSON and Identify Cloud-Related Attacks
Once the JSON files are downloaded, the next step is to parse these files to identify cloud-related attack patterns. This task is performed by the `etape2_parse_json.py` script.

```sh
python etape2_parse_json.py
```

This script analyses the fetched JSON data, filtering for cloud-related attack patterns based on predefined criteria or identifiers.

### Step 3: Modify the MISP Matrix with New Cloud Attack Data
The final step involves modifying the existing MISP matrix to include the new "mitre-cloud-attack" column. The `etape3_modify_raw_with_new_value.py` script accomplishes this.

```sh
python etape3_modify_raw_with_new_value.py
```

This script takes the identified cloud-related attack patterns from Step 2 and integrates them into the MISP matrix, creating or updating the "mitre-cloud-attack" column accordingly.

## Conclusion
By following these steps, users can extend their MISP matrix to include a dedicated column for cloud-related attack patterns, thereby enhancing their threat intelligence capabilities specifically for cloud environments. This project supports the continuous evolution of threat matrices to address the changing landscape of cybersecurity threats.
