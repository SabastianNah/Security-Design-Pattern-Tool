import scrapy
import sqlite3

class CVESpider(scrapy.Spider):
    name = "cwe_crawl"
    allowed_domains = ["cwe.mitre.org"]
    start_url = ["https://cwe.mitre.org/data/definitions/1000.html"]

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
        conn = sqlite3.connect("database_sdp.db")
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
            # Extracting the SDP Hafiz URL
            sdp_url = row[1]

            # Extracting the SDP name
            sdp_name = row[2]

            sdp_keys = row[3]
            # Split sdp_keys into a list of individual keys
            sdp_keys_list = [key.strip() for key in sdp_keys.split(',')]
            sdp_keys_list_lower = [key.lower() for key in sdp_keys_list]

            sdp_related = row[7]
            # Split sdp_related into a list of individual related
            sdp_related_list = [related.strip() for related in sdp_related.split(',')]
            sdp_related_list_lower = [related.lower() for related in sdp_related_list]

            sdp_tags = row[8]
            # Split sdp_tags into a list of individual tags
            sdp_tags_list = [tag.strip() for tag in sdp_tags.split(',')]
            sdp_tags_list_lower = [tag.lower() for tag in sdp_tags_list]

            # parse the cwe id from url
            cwe_id = response.url.replace("https://cwe.mitre.org/data/definitions/", "CWE-").replace(".html", "")

            # Create a list
            results = []
            cleaned_results = []

            ### NAME ###
            # Check if the SDP name is present in the webpage
            if sdp_name.lower() in response.text.lower():
                result = {
                    "RANK:": 1,
                    "SDP:": sdp_name,
                    "SDP URL:": sdp_url,
                    "SEARCH TERM:": sdp_name,
                    "CWE ID:": cwe_id,
                    "CWE URL:": response.url
                }
                results.append(result)
                cleaned_results.append(response.url)

            ### TAGS ###
            # If all tags in sdp_tags_list_lower are in description and are not already in results
            search_terms = all(tag in response.text.lower() for tag in sdp_tags_list_lower)
            if search_terms:
                if response.url not in cleaned_results and any(sdp_tags_list):
                    result = {
                        "RANK:": 2,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(sdp_tags_list_lower),
                        "CWE ID:": cwe_id,
                        "CWE URL:": response.url
                    }
                    results.append(result)
                    cleaned_results.append(response.url)

            ### KEYS ###
            # If all tags in sdp_tags_list_lower are in description and are not already in results
            search_terms = [key for key in sdp_keys_list_lower if key in response.text.lower()]
            if search_terms:
                if response.url not in cleaned_results and any(sdp_keys_list):
                    result = {
                        "RANK:": 3,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(search_terms),
                        "CWE ID:": cwe_id,
                        "CWE URL:": response.url
                    }
                    results.append(result)
                    cleaned_results.append(response.url)

            ### RELATED ###
            # If all tags in sdp_tags_list_lower are in description and are not already in results
            search_terms = [related for related in sdp_related_list_lower if related in response.text.lower()]
            if search_terms:
                if response.url not in cleaned_results and any(sdp_related_list):
                    result = {
                        "RANK:": 4,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(search_terms),
                        "CWE ID:": cwe_id,
                        "CWE URL:": response.url
                    }
                    results.append(result)
                    cleaned_results.append(response.url)

            # Create a connection to the new SQLite database
            conn_cwe = sqlite3.connect("database_sdp.db")
            cursor_cwe = conn_cwe.cursor()

            # Create the cwe_data table if it doesn't exist
            cursor_cwe.execute("""CREATE TABLE IF NOT EXISTS cwe_data (
                                       source_rank INT,
                                       sdp_name TEXT,
                                       sdp_url TEXT,
                                       search_term TEXT,
                                       cwe_id TEXT,
                                       cwe_url TEXT
                                   )""")

            # Iterate through the results and insert into the new database
            for result in results:
                source_rank = result.get("RANK:", "")
                sdp_name = result.get("SDP:", "")
                sdp_url = result.get("SDP URL:", "")
                search_term = result.get("SEARCH TERM:", "")
                cwe_id = result.get("CWE ID:", "")
                cwe_url = result.get("CWE URL:", "")

                # Insert data into the cwe_data table
                cursor_cwe.execute(
                    "INSERT INTO cwe_data (source_rank, sdp_name, sdp_url, search_term, cwe_id, cwe_url) VALUES (?, ?, ?, ?, ?, ?)",
                    (source_rank, sdp_name, sdp_url, search_term, cwe_id, cwe_url))

            # Commit the changes and close the connection to the new database
            conn_cwe.commit()
            conn_cwe.close()

    def closed(self, reason):
        conn = sqlite3.connect("database_sdp.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM cwe_data")

        results = cursor.fetchall()

        for data in results:
            print("RANK:", data[0])
            print("SDP NAME:", data[1])
            print("SDP URL:", data[2])
            print("SEARCH TERM:", data[3])
            print("CWE ID:", data[4])
            print("CWE URL:", data[5])
            print()

        conn.close()
