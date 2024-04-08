import scrapy
import sqlite3

class CVESpider(scrapy.Spider):
    name = "cwe_tester"
    allowed_domains = ["cwe.mitre.org"]
    start_url = ["https://cwe.mitre.org/data/definitions/1000.html"]

    valid_urls = []

    # sdp_name = "Account Lockout"
    # sdp_tags = "Authentication, User Interface"
    # sdp_url = ("https://web.archive.org/web/20190228153557/http://munawarhafiz.com"
    #            "/securitypatterncatalog/patterns.php?name=Account%20Lockout")

    def start_requests(self):
        for url in self.start_url:
            yield scrapy.Request(url, callback=self.parse_catalog)

    def parse_catalog(self, response):
        # Extract links
        cwe_catalog = response.xpath('//a[contains(@href, "/data/definitions/")]/@href').extract()
        cwe_catalog = ["https://cwe.mitre.org" + url for url in cwe_catalog]

        # Iterate through links
        for url in cwe_catalog:
            # Create absolute URL
            absolute_url = response.urljoin(url)

            # Make a request to the linked page
            yield scrapy.Request(absolute_url, callback=self.parse_cwe)

    def parse_cwe(self, response):
        # Connect to SQLite database
        conn = sqlite3.connect('database_hafiz.db')
        cursor = conn.cursor()

        # Execute query to fetch all rows from sdp_hafiz_info
        query = "SELECT * FROM sdp_hafiz_info"
        cursor.execute(query)

        # Fetch all rows
        rows = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        conn.close()

        for row in rows:
            sdp_name = row[2]
            sdp_tags = row[8]

            # Split sdp_tags into a list of individual tags
            sdp_tags_list = [tag.strip() for tag in sdp_tags.split(',')]
            sdp_tags_list_lower = [tag.lower() for tag in sdp_tags_list]

            cwe_id = response.url.replace("https://cwe.mitre.org/data/definitions/", "CWE-").replace(".html", "")

            # Create a list
            results = []
            cleaned_results = []

            # Check if the SDP name is present in the webpage
            if sdp_name.lower() in response.text.lower():
                result = {
                    "SDP:": sdp_name,
                    "SEARCH TERM:": sdp_name,
                    "CWE ID:": cwe_id,
                    "CWE URL:": response.url
                }
                results.append(result)
                cleaned_results.append(response.url)

            # If all tags in sdp_tags_list_lower are in description and are not already in results
            # search_terms = [tag for tag in sdp_tags_list_lower if tag in response.text.lower()]
            search_terms = all(tag in response.text.lower() for tag in sdp_tags_list_lower)
            if search_terms:
                if response.url not in cleaned_results and any(sdp_tags_list):
                    result = {
                        "SDP": sdp_name,
                        "SEARCH TERM:": ", ".join(sdp_tags_list),
                        "CWE ID:": cwe_id,
                        "CWE URL:": response.url
                    }
                    results.append(result)
                    cleaned_results.append(response.url)

            # Print a message indicating that "Account Lockout" was found on the current URL
            for result in results:
                print(result)
