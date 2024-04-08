import scrapy
import sqlite3
from urllib.parse import urlparse, parse_qs, unquote

class CVESpider(scrapy.Spider):
    name = "cve_crawl"
    allowed_domains = ["cve.mitre.org"]

    def start_requests(self):

        conn = sqlite3.connect("database_sdp.db")
        cursor = conn.cursor()

        query = "SELECT * FROM sdp_hafiz_info"
        cursor.execute(query)

        rows = cursor.fetchall()

        cursor.close()
        conn.close()

        for row in rows:
            sdp_url = row[1]
            sdp_name = row[2]
            sdp_keys = row[3]
            sdp_related = row[7]
            sdp_tags = row[8]
            url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={sdp_name}"
            yield scrapy.Request(url=url, callback=self.parse_cve,
                                 meta={'sdp_url': sdp_url,
                                       'sdp_name': sdp_name,
                                       'sdp_keys': sdp_keys,
                                       'sdp_related': sdp_related,
                                       'sdp_tags': sdp_tags})

    def parse_cve(self, response):

        # Extracting the meta
        sdp_url = response.meta.get("sdp_url", '')
        sdp_name = response.meta.get("sdp_name", '')
        sdp_keys = response.meta.get("sdp_keys", '')
        sdp_related = response.meta.get("sdp_related", '')
        sdp_tags = response.meta.get("sdp_tags", '')

        # Split sdp_keys into a list of individual keys
        sdp_keys_list = [key.strip() for key in sdp_keys.split(',')]
        sdp_keys_list_lower = [key.lower() for key in sdp_keys_list]

        # Split sdp_related into a list of individual related
        sdp_related_list = [related.strip() for related in sdp_related.split(',')]
        sdp_related_list_lower = [related.lower() for related in sdp_related_list]

        # Split sdp_tags into a list of individual tags
        sdp_tags_list = [tag.strip() for tag in sdp_tags.split(',')]
        sdp_tags_list_lower = [tag.lower() for tag in sdp_tags_list]

        # Extracting the CVE information
        cve_urls = response.css('#TableWithRules a::attr(href)').extract()
        cve_urls = ["https://cve.mitre.org" + url for url in cve_urls]
        cve_ids = response.xpath('//a[contains(@href, "cvename.cgi?name=CVE")]/text()').getall()
        cve_descriptions = response.css('td[valign="top"]::text').getall()
        cve_descriptions = [desc.strip() for desc in cve_descriptions if desc.strip() and "** RESERVED **" not in desc]

        # Create a list
        results = []
        cleaned_results = []
        for cve_url, cve_id, cve_description in zip(cve_urls, cve_ids, cve_descriptions):

            ### NAMES ###
            # Check if the SDP name is present in the cve description
            if sdp_name.lower() in cve_description.lower():
                result = {
                    "RANK:": 1,
                    "SDP:": sdp_name,
                    "SDP URL:": sdp_url,
                    "SEARCH TERM:": sdp_name,
                    "CVE ID:": cve_id,
                    "CVE URL:": cve_url,
                }
                results.append(result)
                cleaned_results.append(cve_id)

            ### TAGS ###
            # If any cve ids tags are in description and are not already in results
            # search_term = all(tag in cve_description.lower() for tag in sdp_tags_list_lower)
            search_term = [tag for tag in sdp_tags_list_lower if tag in cve_description.lower()]
            if search_term:
                if cve_id not in cleaned_results and any(sdp_tags_list):
                    result = {
                        "RANK:": 2,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(search_term),
                        "CVE ID:": cve_id,
                        "CVE URL:": cve_url,
                    }
                    results.append(result)
                    cleaned_results.append(cve_id)

            ### KEYS ###
            # If all tags in sdp_tags_list_lower are in description and are not already in results
            search_term = [key for key in sdp_keys_list_lower if key in cve_description.lower()]
            if search_term:
                if cve_id not in cleaned_results and any(sdp_keys_list):
                    result = {
                        "RANK:": 3,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(search_term),
                        "CVE ID:": cve_id,
                        "CVE URL:": cve_url,
                    }
                    results.append(result)
                    cleaned_results.append(cve_id)

            ### RELATED ###
            # If all tags in sdp_tags_list_lower are in description and are not already in results
            search_term = [related for related in sdp_related_list_lower if
                           related in cve_description.lower()]
            if search_term:
                if cve_id not in cleaned_results and any(sdp_related_list):
                    result = {
                        "RANK:": 4,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(search_term),
                        "CVE ID:": cve_id,
                        "CVE URL:": cve_url,
                    }
                    results.append(result)
                    cleaned_results.append(cve_id)

        # Create a connection to the new SQLite database
        conn_cve = sqlite3.connect("database_sdp.db")
        cursor_cve = conn_cve.cursor()

        # Create the cve_data table if it doesn't exist
        cursor_cve.execute("""CREATE TABLE IF NOT EXISTS cve_data (
                                               source_rank INT,
                                               sdp_name TEXT,
                                               sdp_url TEXT,
                                               search_term TEXT,
                                               cve_id TEXT,
                                               cve_url TEXT
                                           )""")

        # Iterate through the results and insert into the new database
        for result in results:
            source_rank = result.get("RANK:", "")
            sdp_name = result.get("SDP:", "")
            sdp_url = result.get("SDP URL:", "")
            search_term = result.get("SEARCH TERM:", "")
            cve_id = result.get("CVE ID:", "")
            cve_url = result.get("CVE URL:", "")

            # Insert data into the cve_data table
            cursor_cve.execute(
                "INSERT INTO cve_data (source_rank, sdp_name, sdp_url, search_term, cve_id, cve_url) VALUES (?, ?, ?, ?, ?, ?)",
                (source_rank, sdp_name, sdp_url, search_term, cve_id, cve_url))

        # Commit the changes and close the connection to the new database
        conn_cve.commit()
        conn_cve.close()

    def closed(self, reason):
        conn = sqlite3.connect("database_sdp.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM cve_data")

        results = cursor.fetchall()

        for data in results:
            print("RANK:", data[0])
            print("SDP NAME:", data[1])
            print("SDP URL:", data[2])
            print("SEARCH TERM:", data[3])
            print("CVE ID:", data[4])
            print("CVE URL:", data[5])
            print()

        conn.close()