import scrapy
from lxml import html

class PrivacyPatternsSpider(scrapy.Spider):
    name = 'sdp_tester'
    start_urls = ["https://web.archive.org/web/20190228134321/http://munawarhafiz.com/securitypatterncatalog/patterns.php?name=Brokered%20Authentication"]

    def clean_html_tags(self, html_content):
        # Use lxml to parse the HTML and extract text
        return html.fromstring(html_content).text_content().replace('\n', '')

    def parse(self, response):
        # Extracting the problem content
        problem_content = response.xpath('//h2[contains(text(), "Problem")]/following-sibling::node()').extract()
        solution_index = problem_content.index(
            '<h2 align="left">Solution\n </h2>') if '<h2 align="left">Solution\n </h2>' in problem_content else None
        if solution_index is not None:
            problem_content = problem_content[:solution_index]

        # Join the extracted content into a single string
        problem_text = self.clean_html_tags(''.join(problem_content))
        solution_content = response.xpath('//h2[contains(text(), "Solution")]/following-sibling::node()').extract_first()
        known_uses_content = response.css("font::text")[5].get().strip().replace('\n','').replace("Known Uses", "")
        related_patterns_content = response.xpath('//h2[contains(text(), "Related Patterns")]/following-sibling::node()').extract_first()
        source_content = response.xpath('//h4[contains(text(), "Source")]/following-sibling::node()').extract_first()
        tags_content = response.xpath('//h4[contains(text(), "Tags")]/following-sibling::node()').extract_first()

        result = {
            'problem': problem_text,
            'solution': solution_content,
            'known_uses': known_uses_content,
            'related_patterns': related_patterns_content,
            'source': source_content,
            'tags': tags_content,
        }

        # Print the results
        for key, value in result.items():
            print(f"{key.capitalize()}: {value}\n")