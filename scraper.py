import re
from urllib.parse import urlparse
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from collections import Counter
from urllib.parse import parse_qs, unquote
import atexit
import hashlib
#simhash calculation
def simhash(text, hBits=64):
    words = text.split()
    weights = {}
    
    
    for word in words:
        weights[word] = weights.get(word, 0) + 1

    
    hVec = [0] * hBits

    for word, weight in weights.items():
       
        hashValue = int(hashlib.md5(word.encode()).hexdigest(), 16)  
        hashValue = hashValue & ((1 << hBits) - 1)  

        for i in range(hBits):
            
            bit = 1 if (hashValue & (1 << i)) else -1
            
            hVec[i] += bit * weight


    simValue = 0
    for i in range(hBits):
        if hVec[i] > 0:
            simValue |= (1 << i)  

    return simValue

#hamming distance
def hamDis(hash1, hash2):
    x = hash1 ^ hash2  
    return bin(x).count('1')  

#cut fragments
def normalize_url(url):
    return urldefrag(url)[0]

alredySeenURL = set()  
wordCount = Counter()  
subdUnique = {}
subC = {}  
longestPage = {"url": None, "word_count": 0}  
STOP_WORDS = {
    "the", "and", "a", "an", "to", "is", "in", "that", "it", "on", "for", "with",
    "as", "was", "at", "by", "this", "from", "or", "be", "are", "of", "not", "but",
    "we", "can", "if", "so", "about", "all", "one", "you", "your", "which",
    "have", "has", "they", "their", "there", "some", "my", "our", "more", "will",
    "would", "should", "could"
}
simCache = {}

def scraper(url, resp):
    global alredySeenURL, wordCount, subC, longestPage, subdUnique

    if resp.status in [404, 608, 403, 500]:
        print(f"404 skip:{url}")
        return []
    normalized_url = normalize_url(url)
    
    
    if (normalized_url) in alredySeenURL:
        print(f"seen{normalized_url}")
        return []
    
    if resp.raw_response is None:
        print(f"http no responce: {url}")
        return []
    content_type = resp.raw_response.headers.get("Content-Type", "").lower()#check type
    blocked_types = [
        
            "application/pdf", "application/msword",
            "application/vnd.openxmlformats-officedocument",
            "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            
           
            "application/octet-stream", "application/x-gzip", "application/x-tar",
            "application/zip", "application/x-rar-compressed",
            "application/x-7z-compressed", "application/x-bzip2",
            
            
            "audio/mpeg", "audio/wav", "audio/ogg",
            "video/mp4", "video/mpeg", "video/quicktime",
            "image/png", "image/jpeg", "image/gif", "image/tiff", "image/bmp",
            
            
            "application/javascript", "application/x-sh",
            "application/x-binary", "application/x-executable",
            "application/x-msdownload", "application/x-iso9660-image",
            "application/x-dosexec", "application/x-bzip",
            "application/x-msi", "application/x-ms-shortcut"
    ]
    if any(ext in content_type for ext in blocked_types):
        print(f"file type skip ({content_type}),skip: {url}")
        return []
    alredySeenURL.add((normalized_url))
    print(f"Total unique pages seen: {len(alredySeenURL)}")

    parsed = urlparse(url)
    if parsed.netloc.endswith("ics.uci.edu"):
        if parsed.netloc not in subdUnique:
            subdUnique[parsed.netloc] = set()
        subdUnique[parsed.netloc].add(normalized_url)
    
    links, word_count = extract_next_links(url, resp)


   
    text = " ".join(word_count)  
    simForPage = simhash(text)#get simhash

    
    for old_url, old_hash in simCache.items():#skip or not for simhash
        if hamDis(simForPage, old_hash) < 5:  
            print(f"⚠️ {url} and {old_url} are near same, skip")
            return []

    
    simCache[url] = simForPage

    #word,subdomain, info count
    wordCount.update(word_count)

    
    if word_count and len(word_count) > longestPage["word_count"]:
        longestPage["url"] = url
        longestPage["word_count"] = len(word_count)

    
    parsed = urlparse(url)
    if "ics.uci.edu" in parsed.netloc:
        subC[parsed.netloc] = subC.get(parsed.netloc, 0) + 1

    if len(alredySeenURL) % 1000 == 0:
        print(f"found: {len(alredySeenURL)}, words in total: {len(wordCount)}")

    # return [link for link in links if is_valid(link)]



    return [link for link in links if is_valid(link) and resp.status not in [404, 608]]
   

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    links = []
    word_count = []

    if resp.status != 200 or resp.raw_response is None:
        return links, word_count

    soup = BeautifulSoup(resp.raw_response.content, "lxml")

    
    text = soup.get_text().lower()
    words = re.findall(r"\b[a-zA-Z]{2,}\b", text.lower())  #2 or more
    word_count = [word for word in words if word not in STOP_WORDS]  

    
    for tag in soup.find_all("a"):
        href = tag.get("href")
        if href:
            absolute_url = urljoin(url, href)  
            clean_url = urldefrag(absolute_url)[0]  
            
            links.append(clean_url)
            # links.append(clean_url)

    return links, word_count
    

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    parsed = urlparse(url)

   
    if parsed.scheme not in {"http", "https"}:
        return False

    
    domainOk = {"ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"}
    if not any(parsed.netloc.endswith(domain) for domain in domainOk):
        return False
    
    if any(keyword in parsed.path.lower() for keyword in ["404", "not found"]):#new
        return False

    # if parsed.netloc == "grape.ics.uci.edu":
    #     if parsed.path == "/wiki/public/wiki/cs221-2019-spring" or parsed.path == "":  
    #         return True
    #     else:
    #         print(f"skip grape.ics.uci.edu others: {url}")
    #         return False
    if parsed.netloc == "grape.ics.uci.edu":
        if parsed.path == "/wiki":
            return True  
        elif parsed.path.startswith("/wiki/public/wiki/"):
            sub_path = parsed.path[len("/wiki/public/wiki/"):]  

            
            if "/" not in sub_path and not parsed.query:  
                return True
            else:
                print(f"Skipping deeper path or query in grape.ics.uci.edu: {url}")
                return False
        else:
            print(f"Skipping other grape.ics.uci.edu pages: {url}")
            return False
    
    #avoid trap
    if parsed.netloc == "ngs.ics.uci.edu":
        if parsed.path == "/" or parsed.path == "":
            return True
        else:
            print(f"skip ngs.ics.uci.edu others: {url}")
            return False
        
    if parsed.netloc in ["ics.uci.edu", "www.ics.uci.edu"] and parsed.path.startswith("/~eppstein"):
        if parsed.path not in ["/~eppstein/", "/~eppstein", "/~eppstein/index.html"]:
            print(f"Skipping subpage under ~eppstein: {url}")
            return False
        
    if parsed.netloc == "sli.ics.uci.edu":
        if parsed.path == "/" or parsed.path == "":
            return True
        else:
            print(f"skip sli.ics.uci.edu others: {url}")
            return False

    
    if re.search(
        r"\.(css|js|bmp|gif|jpe?g|ico"
        r"|png|tiff?|mid|mp2|mp3|mp4"
        r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
        r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
        r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
        r"|epub|dll|cnf|tgz|sha1"
        r"|thmx|mso|arff|rtf|jar|csv"
        r"|rm|smil|wmv|swf|wma|zip|rar|gz|bib|img|apk|war|txt|lif)$", parsed.path.lower()):#add more file type
        return False


    decoded_query = unquote(parsed.query)

    
    query_params = parse_qs(decoded_query)
    blacklisted_keys = {"filter", "sort", "category", "session", "eventDisplay", "paged", "tribe-bar-date", "eventDate", "ical"}

   
    if any(key in query_params for key in blacklisted_keys):
        return False

    
    if "filter[" in decoded_query:
        return False
    
    blocked_keywords = ["pdf", "git/?p=iot2.git", "/git", "doku.php", "/pix", "/hotshots", "/supplement"]


    matched_keyword = next((kw for kw in blocked_keywords if kw in url.lower()), None)

    if matched_keyword:
        print(f"skip '{matched_keyword}'  URL: {url}")
        return False


    return True
    


def print_summary():
    print(f"\n Crawling Summary")
    print(f"Total Unique Pages: {len(alredySeenURL)}")
    print(f"Longest Page: {longestPage['url']} ({longestPage['word_count']} words)")
    print("\n Top 50 Words:")
    for word, count in wordCount.most_common(50):
        print(f"{word}: {count}")

    print("\nICS Subdomains (Unique Pages Count):")
    for subdomain in sorted(subdUnique.keys()):  
        print(f"http://{subdomain}, {len(subdUnique[subdomain])}")

atexit.register(print_summary)
