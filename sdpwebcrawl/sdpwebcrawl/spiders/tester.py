import scrapy


class CVESpider(scrapy.Spider):
    name = "tester"
    allowed_domains = ["cwe.mitre.org"]
    start_url = ["https://cwe.mitre.org/data/definitions/1000.html"]

    sdp_name = "Account Lockout"
    sdp_tags = "Authentication, User Interface"
    sdp_keys = "Perimeter Security, Spoofing"
    sdp_related = "Hidden Implementation, Encrypted Storage, Network Address Blacklist"
    sdp_url = ("https://web.archive.org/web/20190228153557/http://munawarhafiz.com"
               "/securitypatterncatalog/patterns.php?name=Account%20Lockout")

    def start_requests(self):
        for url in self.start_url:
            yield scrapy.Request(url, callback=self.parse,
                                 meta={'sdp_name': self.sdp_name,
                                       'sdp_tags': self.sdp_tags,
                                       'sdp_keys': self.sdp_keys,
                                       'sdp_related': self.sdp_related})

    def parse(self, response):
        # Extract links
        cwe_catalog = response.xpath('//a[contains(@href, "/data/definitions/")]/@href').extract()
        cwe_catalog = ["https://cwe.mitre.org" + url for url in cwe_catalog]

        # Extracting the SDP name
        sdp_name = response.meta.get("sdp_name", '')
        sdp_tags = response.meta.get("sdp_tags", '')
        sdp_keys = response.meta.get("sdp_keys", '')
        sdp_related = response.meta.get("sdp_related", '')

        # Iterate through links
        for url in cwe_catalog:
            # Create absolute URL
            absolute_url = response.urljoin(url)

            # Make a request to the linked page
            yield scrapy.Request(absolute_url, callback=self.parse_cwe,
                                 meta={'sdp_name': self.sdp_name,
                                       'sdp_tags': self.sdp_tags,
                                       'sdp_keys': self.sdp_keys,
                                       'sdp_related': self.sdp_related})

    def parse_cwe(self, response):

        # rank of link
        source_rank = "1"

        # Extracting the SDP name
        sdp_name = response.meta.get("sdp_name", '')

        sdp_tags = response.meta.get("sdp_tags", '')
        # Split sdp_tags into a list of individual tags
        sdp_tags_list = [tag.strip() for tag in sdp_tags.split(',')]
        sdp_tags_list_lower = [tag.lower() for tag in sdp_tags_list]

        sdp_keys = response.meta.get("sdp_keys", '')
        # Split sdp_keys into a list of individual keys
        sdp_keys_list = [key.strip() for key in sdp_keys.split(',')]
        sdp_keys_list_lower = [key.lower() for key in sdp_keys_list]

        sdp_related = response.meta.get("sdp_related", '')
        # Split sdp_related into a list of individual related
        sdp_related_list = [related.strip() for related in sdp_related.split(',')]
        sdp_related_list_lower = [related.lower() for related in sdp_related_list]

        cwe_id = response.url.replace("https://cwe.mitre.org/data/definitions/", "CWE-").replace(".html", "")

        # Create a list
        results = []
        cleaned_results = []

        ### NAMES ###
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
            # Print a message indicating that "Account Lockout" was found on the current URL
            print(f"{source_rank} {sdp_name} found in {cwe_id} at url: {response.url} using this {sdp_name}")

        ### TAGS ###
        # If all tags in sdp_tags_list_lower are in description and are not already in results
        # search_terms = [tag for tag in sdp_tags_list_lower if tag in response.text.lower()]
        search_terms = all(tag in response.text.lower() for tag in sdp_tags_list_lower)
        if search_terms:
            if response.url not in cleaned_results and any(sdp_tags_list):
                result = {
                    "SDP:": sdp_name,
                    "SEARCH TERM:": sdp_tags_list,
                    "CWE ID:": cwe_id,
                    "CWE URL:": response.url
                }
                source_rank = "2"
                results.append(result)
                cleaned_results.append(response.url)

                # Print a message indicating that "Account Lockout" was found on the current URL
                print(f"{source_rank} {sdp_name} found in {cwe_id} at url: {response.url} using this {sdp_tags_list}")

        ### KEYS ###
        # If all tags in sdp_tags_list_lower are in description and are not already in results
        search_terms = [key for key in sdp_keys_list_lower if key in response.text.lower()]
        # search_terms = all(key in response.text.lower() for key in sdp_keys_list_lower)
        if search_terms:
            if response.url not in cleaned_results and any(sdp_keys_list):
                result = {
                    "SDP:": sdp_name,
                    "SEARCH TERM:": search_terms,
                    "CWE ID:": cwe_id,
                    "CWE URL:": response.url
                }
                source_rank = "3"
                results.append(result)
                cleaned_results.append(response.url)

                # Print a message indicating that "Account Lockout" was found on the current URL
                print(f"{source_rank} {sdp_name} found in {cwe_id} at url: {response.url} using this {search_terms}")

        ### RELATED ###
        # If all tags in sdp_tags_list_lower are in description and are not already in results
        search_terms = [related for related in sdp_related_list_lower if related in response.text.lower()]
        # search_terms = all(tag in response.text.lower() for tag in sdp_related_list_lower)
        if search_terms:
            if response.url not in cleaned_results and any(sdp_related_list):
                result = {
                    "SDP:": sdp_name,
                    "SEARCH TERM:": search_terms,
                    "CWE ID:": cwe_id,
                    "CWE URL:": response.url
                }
                source_rank = "4"
                results.append(result)
                cleaned_results.append(response.url)

                # Print a message indicating that "Account Lockout" was found on the current URL
                print(f"{source_rank} {sdp_name} found in {cwe_id} at url: {response.url} using this {search_terms}")
