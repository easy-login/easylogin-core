from amazon_pay.client import AmazonPayClient
import json


client = AmazonPayClient(
        mws_access_key='AKIAJQCADG3WKGT46RLA',
        mws_secret_key='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',
        merchant_id='AXRHKH1P12JT4',
        sandbox=True,
        region='us',
        currency_code='USD',
        log_enabled=True,
        log_file_name="/tmp/amzpay.log",
        log_level="DEBUG")

order_id = 'S01-0019078-7407291'
access_token = 'Atza|IwEBIGRkALAWM4HrOiXkZtkY6ru7BI0ce-Y3l7tZMWZFlHM710LDz4gvZtog49OCJ3DjsQy68nXn-RZwuJ7LVUzEnXjp7-NDtTj87nzfbHnbKjfxbqhkgs2Kl_mkypAiGG4HvGXuBgycMrvJiHEAkEBDgMbPq7m9YOts1WqN2q44OqBToZjTJhHdELyUp3xIG0njWk5_xGDOU1J8w-8m-ibg0pAAXbneWSzlbQRyK8splCQ79EDIEoym3QL6jD19R94K8ICU8rL0JYeYJeQuskkei2pDj9qj1GBkAjnNJPivaCBVjqbKrBXhUQ_cX7Zvt-t7RrGNk_RN1rhHeuVyllkbLiOXiJr3qdstaPXbnc3fNP5fZ_NrCqopuE5EhTraYVX00mi2EGOulAKr6BlANIdey1KA8sDGpkM9Nrjv9hbfPFvmEGwG3wFsEHvHazvNIyMKNvrCIEh2qnPeiOqheu-qT9Hr0slvcA5qo-7XFbuTlVNG1jfMKacUJr8mN1PHHYzU05g'

# response = client.close_order_reference(
#     amazon_order_reference_id=order_id,
#     closure_reason='My closure reason.')

response = client.get_order_reference_details(
            amazon_order_reference_id=order_id,
            address_consent_token=access_token)

pretty = json.dumps(json.loads(response.to_json()), indent=4)
print(pretty)
