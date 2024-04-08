import scrapy
import sqlite3
from urllib.parse import urlparse, parse_qs, unquote, quote


class CVESpider(scrapy.Spider):
    name = "nvd_crawl"
    allowed_domains = ["nvd.nist.gov"]

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
            url = (f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview"
                   f"&query={sdp_name}&search_type=all&isCpeNameSearch=false")
            yield scrapy.Request(url=url, callback=self.parse_nvd,
                                 meta={'sdp_url': sdp_url,
                                       'sdp_name': sdp_name,
                                       'sdp_keys': sdp_keys,
                                       'sdp_related': sdp_related,
                                       'sdp_tags': sdp_tags})

    def parse_nvd(self, response):

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

        # Extracting the NVD information
        nvd_urls = response.xpath('//th[@nowrap="nowrap"]/strong/a/@href').getall()
        nvd_urls = ["https://nvd.nist.gov" + url for url in nvd_urls]
        nvd_ids = response.xpath('//th[@nowrap="nowrap"]/strong/a/text()').getall()
        nvd_descriptions = response.xpath('//p[starts-with(@data-testid, "vuln-summary-")]/text()').getall()
        nvd_descriptions = [desc.replace('\n', '').strip() for desc in nvd_descriptions if desc.strip()]

        # Create a list
        results = []
        cleaned_results = []
        for nvd_url, nvd_id, nvd_description in zip(nvd_urls, nvd_ids, nvd_descriptions):

            ### NAMES ###
            # Check if the SDP name is present in the NVD description
            if sdp_name.lower() in nvd_description.lower():
                result = {
                    "RANK:": 1,
                    "SDP:": sdp_name,
                    "SDP URL:": sdp_url,
                    "SEARCH TERM:": sdp_name,
                    "NVD ID:": nvd_id,
                    "NVD URL:": nvd_url,
                }
                results.append(result)
                cleaned_results.append(nvd_id)

            ### TAGS ###
            # If any nvd ids tags are in description and are not already in results
            # search_term = all(tag in nvd_description.lower() for tag in sdp_tags_list_lower)
            search_term = [tag for tag in sdp_tags_list_lower if tag in nvd_description.lower()]
            if search_term:
                if nvd_id not in cleaned_results and any(sdp_tags_list):
                    result = {
                        "RANK:": 2,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(search_term),
                        "NVD ID:": nvd_id,
                        "NVD URL:": nvd_url,
                    }
                    results.append(result)
                    cleaned_results.append(nvd_id)

            ### KEYS ###
            # If all tags in sdp_tags_list_lower are in description and are not already in results
            search_term = [key for key in sdp_keys_list_lower if key in nvd_description.lower()]
            if search_term:
                if nvd_id not in cleaned_results and any(sdp_keys_list):
                    result = {
                        "RANK:": 3,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(search_term),
                        "NVD ID:": nvd_id,
                        "NVD URL:": nvd_url,
                    }
                    results.append(result)
                    cleaned_results.append(nvd_id)

            ### RELATED ###
            # If all tags in sdp_tags_list_lower are in description and are not already in results
            search_term = [related for related in sdp_related_list_lower if
                           related in nvd_description.lower()]
            if search_term:
                if nvd_id not in cleaned_results and any(sdp_related_list):
                    result = {
                        "RANK:": 4,
                        "SDP:": sdp_name,
                        "SDP URL:": sdp_url,
                        "SEARCH TERM:": ", ".join(search_term),
                        "NVD ID:": nvd_id,
                        "NVD URL:": nvd_url,
                    }
                    results.append(result)
                    cleaned_results.append(nvd_id)

        # Create a connection to the new SQLite database
        conn_nvd = sqlite3.connect("database_sdp.db")
        cursor_nvd = conn_nvd.cursor()

        # Create the nvd_data table if it doesn't exist
        cursor_nvd.execute("""CREATE TABLE IF NOT EXISTS nvd_data (
                                       source_rank INT,
                                       sdp_name TEXT,
                                       sdp_url TEXT,
                                       search_term TEXT,
                                       nvd_id TEXT,
                                       nvd_url TEXT
                                   )""")

        # Iterate through the results and insert into the new database
        for result in results:
            source_rank = result.get("RANK:", "")
            sdp_name = result.get("SDP:", "")
            sdp_url = result.get("SDP URL:", "")
            search_term = result.get("SEARCH TERM:", "")
            nvd_id = result.get("NVD ID:", "")
            nvd_url = result.get("NVD URL:", "")

            # Insert data into the nvd_data table
            cursor_nvd.execute(
                "INSERT INTO nvd_data (source_rank, sdp_name, sdp_url, search_term, nvd_id, nvd_url) VALUES (?, ?, ?, ?, ?, ?)",
                (source_rank, sdp_name, sdp_url, search_term, nvd_id, nvd_url))

        # Commit the changes and close the connection to the new database
        conn_nvd.commit()
        conn_nvd.close()

        next_page_url = response.xpath('//li/a[@data-testid="pagination-link-page->"]/@href').extract_first()
        if next_page_url:
            new_url = "https://nvd.nist.gov" + next_page_url
            yield scrapy.Request(url=new_url, callback=self.parse_nvd,
                                 meta={'sdp_url': sdp_url,
                                       'sdp_name': sdp_name,
                                       'sdp_keys': sdp_keys,
                                       'sdp_related': sdp_related,
                                       'sdp_tags': sdp_tags})
        else:
            # Log a warning when next_page_url is None
            self.logger.warning("Next page URL is not available.")

    def closed(self, reason):
        conn = sqlite3.connect("database_sdp.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM nvd_data")

        results = cursor.fetchall()

        for data in results:
            print("RANK:", data[0])
            print("SDP NAME:", data[1])
            print("SDP URL:", data[2])
            print("SEARCH TERM:", data[3])
            print("NVD ID:", data[4])
            print("NVD URL:", data[5])
            print()

        conn.close()
