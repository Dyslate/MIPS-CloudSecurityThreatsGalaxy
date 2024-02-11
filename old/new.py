import requests

# URL de l'API NVD pour récupérer les détails d'une CVE spécifique
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "keywordSearch": "Microsoft Azure",  # Utilisation du mot-clé "Microsoft Azure"
    "resultsPerPage": 1  # Limiter les résultats à la première entrée pour l'exemple
}

# Effectuer la requête
response = requests.get(url, params=params)
data = response.json()

# Afficher le JSON de la première CVE pour le mot-clé spécifié
print(data)