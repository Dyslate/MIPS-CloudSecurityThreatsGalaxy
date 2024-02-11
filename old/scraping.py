import requests
import json
import uuid
import os

class NvdApi:
    """
    Classe pour interagir avec l'API du NVD pour récupérer les données de vulnérabilité.
    """
    def __init__(self, base_url="https://services.nvd.nist.gov/rest/json/cves/2.0"):
        self.base_url = base_url

    def fetch_data(self, keywords, results_per_page=10):
        """
        Récupère les données des vulnérabilités pour les mots-clés donnés.
        """

        all_data = []
        for keyword in keywords:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page
            }
            try:
                response = requests.get(self.base_url, params=params)
                response.raise_for_status()  # Déclencher une exception pour les réponses HTTP non réussies
                data = response.json()
                all_data.extend(data.get('vulnerabilities', []))
            except requests.RequestException as e:
                print(f"Failed to fetch data for keyword '{keyword}': {e}")
        return {"vulnerabilities": all_data}

    def format_for_misp(self, nvd_data, existing_cluster):
        """
        Formatte les données NVD pour être compatibles avec la structure de cluster MISP.
        """
        existing_cve_ids = {value['meta']['cve-id'] for value in existing_cluster.get('values', []) if 'cve-id' in value['meta']}

        for vulnerability in nvd_data.get('vulnerabilities', []):
            cve = vulnerability.get('cve', {})
            cve_id = cve.get('id', '')

            if cve_id in existing_cve_ids:
                print(f"CVE ID {cve_id} already present in the cluster, skipped.")
                continue

            descriptions = cve.get('descriptions', [])
            description_en = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
            references = cve.get('references', [])
            reference_urls = [ref['url'] for ref in references]

            # Extraction des scores CVSS v2 et v3
            metrics_v2 = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0]
            metrics_v3 = cve.get('metrics', {}).get('cvssMetricV3', [{}])[0]

            base_score_v2 = metrics_v2.get('cvssData', {}).get('baseScore', "Unknown")
            severity_v2 = metrics_v2.get('baseSeverity', "Unknown")
            vector_v2 = metrics_v2.get('cvssData', {}).get('vectorString', "Unknown")

            base_score_v3 = metrics_v3.get('cvssData', {}).get('baseScore', "Unknown")
            severity_v3 = metrics_v3.get('baseSeverity', "Unknown")
            vector_v3 = metrics_v3.get('cvssData', {}).get('vectorString', "Unknown")

            # Extraction de la configuration affectée
            configurations = cve.get('configurations', [{}])[0].get('nodes', [])
            affected_configurations = [cpe['criteria'] for node in configurations for cpe in node.get('cpeMatch', [])]

            cluster_value = {
                "description": description_en,
                "meta": {
                    "cve-id": cve_id,
                    "published": cve.get('published', ''),
                    "lastModified": cve.get('lastModified', ''),
                    "source": cve.get('sourceIdentifier', ''),
                    "vulnStatus": cve.get('vulnStatus', ''),
                    "severity_v2": severity_v2,
                    "score_cvss_v2": base_score_v2,
                    "vector_v2": vector_v2,
                    "severity_v3": severity_v3,
                    "score_cvss_v3": base_score_v3,
                    "vector_v3": vector_v3,
                    "cwe": cve.get('weaknesses', [{}])[0].get('description', [{}])[0].get('value', "Unknown"),
                    "affected_configurations": affected_configurations,
                    "references": reference_urls
                },
                "uuid": str(uuid.uuid4()),
                "value": cve_id
            }

            # Ajouter les nouvelles valeurs au cluster existant
            existing_cluster['values'].append(cluster_value)
        return existing_cluster


   

    def update_misp_cluster_file(self, relative_path, new_data):
        """
        Met à jour le fichier cluster MISP avec de nouvelles données.
        """
        dir_path = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(dir_path, relative_path)
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                json.dump(new_data, file, indent=4)
            print("Cluster file successfully updated.")
        except Exception as e:
            print(f"Error updating file: {e}")



# Utilisation
nvd_api = NvdApi()
keywords = ["Microsoft Azure"]
relative_path = 'clusters/cloud_threat_clusters.json'

try:
    with open(relative_path, 'r', encoding='utf-8') as file:
        existing_cluster = json.load(file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"Error reading the cluster file: {e}")
    existing_cluster = {"values": []}


try:
    nvd_data = nvd_api.fetch_data(keywords, results_per_page=5)
    updated_cluster = nvd_api.format_for_misp(nvd_data, existing_cluster)
    nvd_api.update_misp_cluster_file(relative_path, updated_cluster)
except Exception as e:
    print(f"Error occurred: {e}")



