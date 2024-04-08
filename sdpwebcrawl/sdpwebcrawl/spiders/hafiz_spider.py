from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
from urllib.parse import urlparse, parse_qs, unquote
from lxml import html
import re
import sqlite3

class SDPSpider(CrawlSpider):
    name = "hafiz_crawl"
    allowed_domains = ["web.archive.org"]
    start_urls = ["https://web.archive.org/web/20180124090202/http://www.munawarhafiz.com/securitypatterncatalog/"]

    rules = (
        Rule(LinkExtractor(allow="www.munawarhafiz.com/securitypatterncatalog/patterns"),  callback="parse_sdp"),
    )

    # SQLite Database Connection and Table Creation
    conn = sqlite3.connect("database_sdp.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sdp_hafiz_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url BLOB,
            name TEXT,
            class_key TEXT,
            problem BLOB,
            solution BLOB,
            known_uses BLOB,
            related_patterns BLOB,
            tags BLOB
        )
    """)
    conn.commit()

    def clean_html(self, html_content):
        # Use lxml to parse the HTML and extract text
        return html.fromstring(html_content).text_content().replace('\n', '')

    def parse_sdp(self, response):

        # Check if the link matches the specific condition for customization
        if "https://web.archive.org/web/20190228153045/http://munawarhafiz.com/securitypatterncatalog/patterns.php?name=Hidden%20Metadata" in response.url:
            known_uses =re.sub(r'\s+', ' ', response.css("font::text")[5].get().strip().replace('\n','').replace("Known Uses", ""))
        else:
            known_uses = response.xpath(
                '//h2[contains(text(), "Known Uses")]/following-sibling::text()').extract_first().replace('\n', '')

        # Extracting the problem content
        problem_content = response.xpath('//h2[contains(text(), "Problem")]/following-sibling::node()').extract()
        solution_index = problem_content.index(
            '<h2 align="left">Solution\n </h2>') if '<h2 align="left">Solution\n </h2>' in problem_content else None
        if solution_index is not None:
            problem_content = problem_content[:solution_index]

        # Extracting the 'name' parameter from the URL and replacing %20 with a space
        url = response.url
        name_parameter = parse_qs(urlparse(url).query).get("name", [''])[0]
        name_parameter = unquote(name_parameter.replace('%20', ' '))

        # Extracting class_key and removing "Classification Key\n : "
        class_key = response.css("h5::text").get()
        class_key = class_key.replace("Classification Key\n : ", "").strip().replace('\n', '')

        # Extracting tag
        font_text_elements = response.css("font::text").getall()
        size_of_font_text = len(font_text_elements)

        # Extracting .Section1 links to other sdps
        s1_links = response.css(".Section1 a::attr(href)").getall()
        s1_links = [link.replace("patterns.php?name=", "") for link in s1_links]
        related_patterns = ', '.join(s1_links)

        data = {
            "url": response.url,
            "name": name_parameter,
            "class_key": class_key,
            "problem": re.sub(r'\s+', ' ',self.clean_html(''.join(problem_content))),
            "solution": re.sub(r'\s+', ' ', response.xpath('//h2[contains(text(), "Solution")]/following-sibling::node()').extract_first()),
            "known_uses": known_uses,
            "related_patterns": related_patterns,
            "tags": re.sub(r'\s+', ' ', response.css("font::text")[size_of_font_text-2].get().strip().replace('\n',''))
        }

        # SQLite Database Insertion
        self.cur.execute("""
            INSERT INTO sdp_hafiz_info 
            (url, name, class_key, problem, solution, known_uses, related_patterns, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["url"],
            data["name"],
            data["class_key"],
            data["problem"],
            data["solution"],
            data["known_uses"],
            data["related_patterns"],
            data["tags"]
        ))

        self.conn.commit()

        yield data

    def closed(self, reason):
        conn = sqlite3.connect("database_sdp.db")
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM sdp_hafiz_info')

        results = cursor.fetchall()

        for result in results:
            print("URL:", result[1])
            print("NAME:", result[2])
            print("CLASS_KEY:", result[3])
            print("PROBLEM:", result[4])
            print("SOLUTION:", result[5])
            print("KNOWN_USES:", result[6])
            print("RELATED PATTERNS:", result[7])
            print("TAGS:", result[8])
            print()

        conn.close()
