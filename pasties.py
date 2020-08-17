from bs4 import BeautifulSoup
import requests
import warnings
warnings.filterwarnings("ignore")
r  = requests.get("https://haveibeenpwned.com/Pastes/Latest",verify=False)
data = r.text
soup = BeautifulSoup(data)
tablewithlinks = soup.find('table', attrs={'class':'table table-bordered'})
for pastes in tablewithlinks.find_all('a'):
    print(pastes.get('href')) 