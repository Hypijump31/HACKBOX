import requests
from bs4 import BeautifulSoup
import time
import random

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}

GOOGLE_SEARCH_URL = "https://www.google.com/search"

def scrape_google_dork(dork, max_results=3, pause_range=(1, 2)):
    """
    Scrape Google search results for a given dork.
    Returns a list of (title, url) tuples.
    """
    params = {"q": dork, "num": max_results}
    try:
        resp = requests.get(GOOGLE_SEARCH_URL, params=params, headers=HEADERS, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        return [(f"Erreur lors de la requête Google: {e}", "")]  # Return error as a result
    soup = BeautifulSoup(resp.text, "html.parser")
    results = []
    for g in soup.select("div.g"):
        link = g.find("a", href=True)
        title = g.find("h3")
        if link and title:
            results.append((title.text.strip(), link['href']))
        if len(results) >= max_results:
            break
    if not results:
        results.append(("Aucun résultat trouvé.", ""))
    # Respect Google ToS: pause entre les requêtes
    time.sleep(random.uniform(*pause_range))
    return results
