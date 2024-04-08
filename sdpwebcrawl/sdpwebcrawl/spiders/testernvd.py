import scrapy
from urllib.parse import urlparse, parse_qs, unquote, quote


class CVESpider(scrapy.Spider):
    name = "nve_tester"
    allowed_domains = ["nvd.nist.gov"]

    def start_requests(self):
        # Search for a sdp by name
        sdp_name = "Account Lockout"
        sdp_tags = "Authentication, User Interface"
        sdp_url = ("https://web.archive.org/web/20190228153557/http://munawarhafiz.com"
                   "/securitypatterncatalog/patterns.php?name=Account%20Lockout")
        url = (f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview"
               f"&query={sdp_name}&search_type=all&isCpeNameSearch=false")

        yield scrapy.Request(url=url, callback=self.parse_nvd,
                             meta={'sdp_url': sdp_url, 'sdp_name': sdp_name, 'sdp_tags': sdp_tags})

    def parse_nvd(self, response):
        # Extracting the SDP url
        sdp_url = response.meta.get('sdp_url', '')

        # Extracting the SDP name
        sdp_name = response.meta.get('sdp_name', '')

        # Extracting the SDP tags
        sdp_tags = response.meta.get('sdp_tags', '')
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

        # Check if the SDP name is present in the NVD description
        for nvd_url, nvd_id, nvd_description in zip(nvd_urls, nvd_ids, nvd_descriptions):
            if sdp_name.lower() in nvd_description.lower():
                result = {
                    "SDP": sdp_name,
                    "SEARCH TERM:": sdp_name,
                    "SDP URL:": sdp_url,
                    "NVD URL": nvd_url,
                    "NVD ID": nvd_id,
                    "NVD Description": nvd_description,
                }
                results.append(result)
                cleaned_results.append(nvd_id)

            # If any nvd ids tags are in description and are not already in results
            search_term = [tag for tag in sdp_tags_list_lower if tag in nvd_description.lower()]
            if search_term:
                if nvd_id not in cleaned_results:
                    result = {
                        "SDP": sdp_name,
                        "SEARCH TERM:": search_term,
                        "SDP URL:": sdp_url,
                        "NVD URL": nvd_url,
                        "NVD ID": nvd_id,
                        "NVD Description": nvd_description,
                    }
                    results.append(result)
                    cleaned_results.append(nvd_id)
        next_page_url = response.xpath('//li/a[@data-testid="pagination-link-page->"]/@href').extract_first()

        if next_page_url:
            new_url = "https://nvd.nist.gov" + next_page_url
            yield scrapy.Request(url=new_url, callback=self.parse_nvd,
                                 meta={'sdp_url': sdp_url, 'sdp_name': sdp_name, 'sdp_tags': sdp_tags})
        else:
            # Log a warning when next_page_url is None
            self.logger.warning("Next page URL is not available.")
        # Print the formatted results
        for result in results:
            print(result)