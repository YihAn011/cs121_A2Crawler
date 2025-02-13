# -*- coding: utf-8 -*-

# 导入 scraper.py 中的函数
from scraper import scraper
from collections import namedtuple

# 创建模拟的 Response 对象
MockResponse = namedtuple("MockResponse", ["status", "raw_response"])
MockRawResponse = namedtuple("MockRawResponse", ["content"])

# 伪造 HTML 网页内容，包含各种链接（注意：这里去掉了 b""）
html_content = """
<html>
    <body>
        <a href="/about">About Us</a>
        <a href="https://www.cs.uci.edu/research">Research</a>
        <a href="contact.html">Contact</a>
        <a href="image.jpg">An Image</a>  <!-- 无效的图片链接 -->
        <a href="video.mp4">A Video</a>   <!-- 无效的视频链接 -->
    </body>
</html>
"""

# 创建模拟的 HTTP Response 对象
class FakeResponse:
    def __init__(self, url, content):
        self.status = 200
        self.raw_response = self
        self.url = url
        self.content = content.encode("utf-8")  # 转换成 UTF-8 编码的 bytes

mock_resp = FakeResponse("https://www.ics.uci.edu", html_content)

# 调用 scraper 进行测试
valid_links = scraper(mock_resp.url, mock_resp)

# 输出测试结果
print("最终有效的超链接：")
for link in valid_links:
    print(link)
