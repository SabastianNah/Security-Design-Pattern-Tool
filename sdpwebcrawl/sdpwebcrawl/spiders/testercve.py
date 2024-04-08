import scrapy
from urllib.parse import urlparse, parse_qs, unquote


class CVESpider(scrapy.Spider):
    name = "cve_tester"
    allowed_domains = ["cve.mitre.org"]

    def start_requests(self):
        # Change the key to search a sdp
        key = "Account Lockout"
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={key}"
        yield scrapy.Request(url=url, callback=self.parse_cve)

    def parse_cve(self, response):
        # Extracting the SDP name
        sdp_name = parse_qs(urlparse(response.url).query).get("keyword", [''])[0]
        sdp_name = unquote(sdp_name.replace('%20', ' '))

        # Extracting the CVE information
        cve_urls = response.css('#TableWithRules a::attr(href)').extract()
        cve_urls = ["https://cve.mitre.org" + url for url in cve_urls]

        cve_ids = response.xpath('//a[contains(@href, "cvename.cgi?name=CVE")]/text()').getall()

        cve_descriptions = response.css('td[valign="top"]::text').getall()
        cve_descriptions = [desc.strip() for desc in cve_descriptions if desc.strip()]

        # Create a list of dictionaries
        results = []
        keywords_set1 = {"account lockout"}
        keywords_set2 = {"account lockout"}
        keywords_set3 = {"account lockout"}

        for cve_url, cve_id, cve_description in zip(cve_urls, cve_ids, cve_descriptions):
            # Check if both conditions are met (ignoring capitalization)
            if (all(keyword.lower() in cve_description.lower() for keyword in keywords_set1) or
                    all(keyword.lower() in cve_description.lower() for keyword in keywords_set2) or
                    all(keyword.lower() in cve_description.lower() for keyword in keywords_set3)):
                result = {
                    "SDP": sdp_name,
                    "CVE URL": cve_url,
                    "CVE ID": cve_id,
                    "CVE Description": cve_description,
                }
                results.append(result)

        # Print the formatted results
        for result in results:
            print(result)
