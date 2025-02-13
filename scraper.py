import re
from urllib.parse import urlparse
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from collections import Counter
from urllib.parse import parse_qs, unquote
import atexit
import hashlib

def simhash(text, hash_bits=64):
    words = text.split()
    weights = {}
    
    # 统计词频
    for word in words:
        weights[word] = weights.get(word, 0) + 1

    # 初始化哈希向量
    hash_vector = [0] * hash_bits

    for word, weight in weights.items():
        # 计算单词的哈希值（64 位二进制）
        hash_value = int(hashlib.md5(word.encode()).hexdigest(), 16)  # 128-bit MD5 哈希
        hash_value = hash_value & ((1 << hash_bits) - 1)  # 取低 64 位

        for i in range(hash_bits):
            # 提取哈希值的第 i 位
            bit = 1 if (hash_value & (1 << i)) else -1
            # 根据单词的权重调整哈希向量
            hash_vector[i] += bit * weight

    # 归一化二进制哈希
    simhash_value = 0
    for i in range(hash_bits):
        if hash_vector[i] > 0:
            simhash_value |= (1 << i)  # 设为 1

    return simhash_value

def hamming_distance(hash1, hash2):
    x = hash1 ^ hash2  # 计算异或
    return bin(x).count('1')  # 计算二进制中 1 的个数

def normalize_url(url):
    parsed = urlparse(url)
    query_params = frozenset((k, tuple(v)) for k, v in parse_qs(parsed.query).items() if k not in {"tribe-bar-date", "eventDate", "ical", "paged"})
    normalized = parsed._replace(query="").geturl()  
    return (normalized, query_params)
seenUrls = set()  
word_counter = Counter()  
subdomain_count = {}  
longest_page = {"url": None, "word_count": 0}  
STOP_WORDS = {
    "the", "and", "a", "an", "to", "is", "in", "that", "it", "on", "for", "with",
    "as", "was", "at", "by", "this", "from", "or", "be", "are", "of", "not", "but",
    "we", "can", "if", "so", "about", "all", "one", "you", "your", "which",
    "have", "has", "they", "their", "there", "some", "my", "our", "more", "will",
    "would", "should", "could"
}
simhash_cache = {}

def scraper(url, resp):
    global seenUrls, word_counter, subdomain_count, longest_page

    clean_url = urldefrag(url)[0]
    
    # 1. 过滤 404 页面
    if resp.status in [404, 608]:
        return []
    
    normalized_url, query_params = normalize_url(url)
    # 2. 避免重复访问
    if (normalized_url, query_params) in seenUrls:
        return []
    seenUrls.add((normalized_url, query_params))

    # 3. 解析 HTML 内容
    links, word_count = extract_next_links(url, resp)


   # **4. 计算当前页面的 SimHash**
    text = " ".join(word_count)  # 重新组合文本
    page_simhash = simhash(text)

    # **5. 近似重复检测**
    for old_url, old_hash in simhash_cache.items():
        if hamming_distance(page_simhash, old_hash) < 5:  # 设定汉明距离阈值
            print(f"⚠️ {url} 与 {old_url} 是近似重复页面，跳过！")
            return []

    # **6. 存储当前页面的 SimHash**
    simhash_cache[url] = page_simhash

    # **7. 统计单词数量**
    word_counter.update(word_count)

    # **8. 记录最长的页面**
    if word_count and len(word_count) > longest_page["word_count"]:
        longest_page["url"] = url
        longest_page["word_count"] = len(word_count)

    # **9. 统计 ics.uci.edu 子域名**
    parsed = urlparse(url)
    if "ics.uci.edu" in parsed.netloc:
        subdomain_count[parsed.netloc] = subdomain_count.get(parsed.netloc, 0) + 1

    if len(seenUrls) % 1000 == 0:
        print(f"✅ 已爬取页面数: {len(seenUrls)}, 发现单词数: {len(word_counter)}")

    # return [link for link in links if is_valid(link)]



    return [link for link in links if is_valid(link) and resp.status not in [404, 608]]
    # global seenUrls

    # # 1. 先去掉 fragment，防止重复爬取相同页面
    # clean_url = urldefrag(url)[0]
    # if clean_url in seenUrls:
    #     return []
    # seenUrls.add(clean_url)

    # links = extract_next_links(url, resp)
    # return [link for link in links if is_valid(link)]

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

    soup = BeautifulSoup(resp.raw_response.content, "html.parser")

    # 1. 统计页面中的单词
    text = soup.get_text()
    words = re.findall(r"\b[a-zA-Z]{2,}\b", text.lower())  # 仅统计 2 个字母以上的单词
    word_count = [word for word in words if word not in STOP_WORDS]  # 过滤掉常见停用词

    # 2. 提取超链接
    for tag in soup.find_all("a"):
        href = tag.get("href")
        if href:
            absolute_url = urljoin(url, href)  # 处理相对路径
            clean_url = urldefrag(absolute_url)[0]  # 去掉 fragment
            links.append(clean_url)

    return links, word_count
    # links = []
    # if resp.status != 200 or resp.raw_response is None:
    #     return links
    
    # soup = BeautifulSoup(resp.raw_response.content, "html.parser")
    # for tag in soup.find_all("a"):
    #     href = tag.get("href")
    #     if href:
    #         absoluteUrl = urljoin(url, href)
    #         cleanUrl = urldefrag(absoluteUrl)[0]
    #         links.append(cleanUrl)
    # return links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    parsed = urlparse(url)

    # 1. 仅允许 HTTP 和 HTTPS 协议
    if parsed.scheme not in {"http", "https"}:
        return False

    # 2. 仅爬取 UCI 相关域名
    allowed_domains = {"ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"}
    if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
        return False

    # 3. 过滤无用文件类型
    if re.search(
        r"\.(css|js|bmp|gif|jpe?g|ico"
        r"|png|tiff?|mid|mp2|mp3|mp4"
        r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
        r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
        r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
        r"|epub|dll|cnf|tgz|sha1"
        r"|thmx|mso|arff|rtf|jar|csv"
        r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
        return False

    # 4. 过滤常见无用的 URL 参数
    # blacklist_keywords = ["?ical=", "eventDisplay=past", "page=", "/tag/", "/author=", 
    #     "?filter=", "?sort=", "?session=", "?category=", "?set=", 
    #     "&filter=", "&sort=", "&session=", "&category=", "&set=", r"[\?&]filter%"]
    # if any(keyword in parsed.path or keyword in parsed.query for keyword in blacklist_keywords):
    #     return False
    decoded_query = unquote(parsed.query)

    # 解析 query 并检查黑名单
    query_params = parse_qs(decoded_query)
    blacklisted_keys = {"filter", "sort", "category", "session", "eventDisplay", "paged", "tribe-bar-date", "eventDate", "ical"}

    # **检查 query 参数是否包含黑名单**
    if any(key in query_params for key in blacklisted_keys):
        return False

    # **检查解码后的 query 是否仍然包含 `filter[`**
    if "filter[" in decoded_query:
        return False
    # query_params = parse_qs(parsed.query)  # 解析 query 参数为字典
    # blacklisted_keys = {"filter", "sort", "category", "session"}  # 需要屏蔽的参数
    # if any(key in query_params for key in blacklisted_keys):
    #     return False

    return True
    # try:
    #     parsed = urlparse(url)
    #     if parsed.scheme not in set(["http", "https"]):
    #         return False
    #     return not re.match(
    #         r".*\.(css|js|bmp|gif|jpe?g|ico"
    #         + r"|png|tiff?|mid|mp2|mp3|mp4"
    #         + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
    #         + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
    #         + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
    #         + r"|epub|dll|cnf|tgz|sha1"
    #         + r"|thmx|mso|arff|rtf|jar|csv"
    #         + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    # except TypeError:
    #     print ("TypeError for ", parsed)
    #     raise


def print_summary():
    print(f"\n🚀 Crawling Summary 🚀")
    print(f"Total Unique Pages: {len(seenUrls)}")
    print(f"Longest Page: {longest_page['url']} ({longest_page['word_count']} words)")
    print("\n📌 Top 50 Words:")
    for word, count in word_counter.most_common(50):
        print(f"{word}: {count}")

    print("\n🌐 ICS Subdomains:")
    for domain, count in sorted(subdomain_count.items()):
        print(f"{domain}, {count}")


atexit.register(print_summary)
