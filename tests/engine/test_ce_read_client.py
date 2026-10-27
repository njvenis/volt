import json
import unittest

from uvm.engine.ce_read_client import (
    CEReadClient, HTTPError, JSONError, PaginationError, RawResponse, ScopeError, ShapeError,
    TransportError,
)


class Fake:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, method, url, headers, timeout, *, follow_redirects):
        self.calls.append((method, url, headers, timeout, follow_redirects))
        try:
            return self.responses[url]
        except KeyError as exc:
            raise AssertionError(url) from exc


def response(body, status=200, headers=None):
    return status, headers or {"Content-Type": "application/json"}, json.dumps(body).encode()


class CEReadClientTests(unittest.TestCase):
    def client(self, responses):
        fake = Fake(responses)
        return CEReadClient("https://dojo.example", fake, token="secret", timeout=4), fake

    def test_paginated_findings_preserves_raw_pages_and_auth_boundary(self):
        one = "https://dojo.example/api/v2/findings/?test=7"
        two = "https://dojo.example/api/v2/findings/?offset=1&test=7"
        client, fake = self.client({
            one: response({"count": 2, "next": two, "results": [{"id": 1, "test": 7}]}),
            two: response({"count": 2, "next": None, "results": [{"id": 2, "test": {"id": 7}}]}),
        })
        result = client.list_findings(test_id=7)
        self.assertEqual([x["id"] for x in result.items], [1, 2])
        self.assertEqual(result.pages[0].body, response({"count": 2, "next": two, "results": [{"id": 1, "test": 7}]})[2])
        self.assertEqual(fake.calls[0][0], "GET")
        self.assertEqual(fake.calls[0][2]["Authorization"], "Token secret")
        self.assertFalse(fake.calls[0][4])

    def test_paginated_endpoints_preserves_raw_pages_auth_and_product_filter(self):
        one = "https://dojo.example/api/v2/endpoints/?host=web-1&product=7"
        two = "https://dojo.example/api/v2/endpoints/?offset=1&host=web-1&product=7"
        client, fake = self.client({
            one: response({"count": 2, "next": two, "results": [{"id": 1, "product": 7}]}),
            two: response({"count": 2, "next": None, "results": [{"id": 2, "product": {"id": 7}}]}),
        })

        result = client.list_endpoints(product_id=7, host="web-1")

        self.assertEqual([item["id"] for item in result.items], [1, 2])
        self.assertEqual(len(result.pages), 2)
        self.assertEqual(fake.calls[0][2]["Authorization"], "Token secret")
        self.assertFalse(fake.calls[0][4])

    def test_endpoint_raw_product_filter_is_rejected_before_transport(self):
        for raw_product in (0, 9):
            with self.subTest(raw_product=raw_product):
                client, fake = self.client({})

                with self.assertRaises(ShapeError):
                    client.list_endpoints(product=raw_product)

                self.assertEqual(fake.calls, [])

    def test_endpoint_scope_error_on_first_page_preserves_exact_raw_response(self):
        requested = "https://dojo.example/api/v2/endpoints/?product=7"
        raw = response({"count": 1, "next": None, "results": [{"id": 1, "product": 9}]})
        client, fake = self.client({requested: raw})

        with self.assertRaises(ScopeError) as ctx:
            client.list_endpoints(product_id=7)

        self.assertEqual(ctx.exception.response.body, raw[2])
        self.assertEqual(len(fake.calls), 1)

    def test_endpoint_scope_error_on_later_page_preserves_exact_raw_response(self):
        one = "https://dojo.example/api/v2/endpoints/?product=7"
        two = "https://dojo.example/api/v2/endpoints/?offset=1&product=7"
        first = response({"count": 2, "next": two, "results": [{"id": 1, "product": 7}]})
        second = response({"count": 2, "next": None, "results": [{"id": 2, "product": 9}]})
        client, fake = self.client({one: first, two: second})

        with self.assertRaises(ScopeError) as ctx:
            client.list_endpoints(product_id=7)

        self.assertEqual(ctx.exception.response.body, second[2])
        self.assertEqual(len(fake.calls), 2)

    def test_endpoint_malformed_product_values_preserve_exact_raw_response(self):
        malformed = (None, 0, "7", [], {"id": None})
        for value in malformed:
            with self.subTest(value=value):
                requested = "https://dojo.example/api/v2/endpoints/?product=7"
                raw = response({
                    "count": 1,
                    "next": None,
                    "results": [{"id": 1, "product": value}],
                })
                client, fake = self.client({requested: raw})

                with self.assertRaises(ShapeError) as ctx:
                    client.list_endpoints(product_id=7)

                self.assertEqual(ctx.exception.response.body, raw[2])
                self.assertEqual(len(fake.calls), 1)

    def test_endpoint_scope_error_preserves_exact_raw_response(self):
        requested = "https://dojo.example/api/v2/endpoints/8/"
        raw = response({"id": 8, "product": 3})
        client, fake = self.client({requested: raw})

        with self.assertRaises(ScopeError) as ctx:
            client.get_endpoint(8, product_id=4)

        self.assertEqual(ctx.exception.response.body, raw[2])
        self.assertEqual(len(fake.calls), 1)

    def test_endpoint_detail_preserves_raw_response(self):
        requested = "https://dojo.example/api/v2/endpoints/8/"
        raw = response({"id": 8, "product": 3, "host": "web-1"})
        client, _ = self.client({requested: raw})

        result = client.get_endpoint(8)

        self.assertEqual(result.data["host"], "web-1")
        self.assertEqual(result.response.body, raw[2])

    def test_findings_scope_error_attaches_offending_page_response(self):
        one = "https://dojo.example/api/v2/findings/?test=7"
        two = "https://dojo.example/api/v2/findings/?offset=1&test=7"
        first = response({"count": 2, "next": two, "results": [{"id": 1, "test": 8}]})
        second = response({"count": 2, "next": None, "results": [{"id": 2, "test": 7}]})
        client, fake = self.client({one: first, two: second})
        with self.assertRaises(ScopeError) as ctx:
            client.list_findings(test_id=7)
        self.assertEqual(ctx.exception.response.body, first[2])
        self.assertEqual(len(fake.calls), 1)

    def test_engagement_scope_error_attaches_offending_page_response(self):
        one = "https://dojo.example/api/v2/engagements/?product=7"
        two = "https://dojo.example/api/v2/engagements/?offset=1&product=7"
        first = response({"count": 2, "next": two, "results": [{"id": 1, "product": 8}]})
        second = response({"count": 2, "next": None, "results": [{"id": 2, "product": 7}]})
        client, fake = self.client({one: first, two: second})
        with self.assertRaises(ScopeError) as ctx:
            client.list_engagements(product_id=7)
        self.assertEqual(ctx.exception.response.body, first[2])
        self.assertEqual(len(fake.calls), 1)

    def test_test_scope_error_attaches_offending_page_response(self):
        one = "https://dojo.example/api/v2/tests/?engagement=7"
        two = "https://dojo.example/api/v2/tests/?offset=1&engagement=7"
        first = response({"count": 2, "next": two, "results": [{"id": 1, "engagement": 8}]})
        second = response({"count": 2, "next": None, "results": [{"id": 2, "engagement": 7}]})
        client, fake = self.client({one: first, two: second})
        with self.assertRaises(ScopeError) as ctx:
            client.list_tests(engagement_id=7)
        self.assertEqual(ctx.exception.response.body, first[2])
        self.assertEqual(len(fake.calls), 1)

    def test_token_rejects_header_injection_characters(self):
        with self.assertRaises(ValueError):
            CEReadClient("https://dojo.example", Fake({}), token="secret\r\nX-Leak: yes")

    def test_base_url_rejects_empty_query_or_fragment_delimiters(self):
        for base_url in ("https://dojo.example?", "https://dojo.example#"):
            with self.subTest(base_url=base_url):
                with self.assertRaises(ValueError):
                    CEReadClient(base_url, Fake({}))

    def test_base_url_is_canonical_and_read_only(self):
        client = CEReadClient("HTTPS://DOJO.EXAMPLE/dojo/", Fake({}))
        self.assertEqual(client.base_url, "https://dojo.example/dojo")
        self.assertEqual(client.normalized_base_url, client.base_url)
        with self.assertRaises(AttributeError):
            client.base_url = "https://other.example"

    def test_malformed_json_preserves_exact_raw_response(self):
        requested = "https://dojo.example/api/v2/products/1/"
        raw = (200, {"Content-Type": "application/json"}, b"not-json")
        client = CEReadClient("https://dojo.example", Fake({requested: raw}))
        with self.assertRaises(JSONError) as ctx:
            client.get_product(1)
        self.assertEqual(ctx.exception.response.body, raw[2])
        self.assertEqual(ctx.exception.response.url, requested)

    def test_duplicate_json_keys_are_rejected_before_parent_scope_checks(self):
        requested = "https://dojo.example/api/v2/engagements/11/"
        body = b'{"id":11,"product":7,"product":8}'
        client = CEReadClient("https://dojo.example", Fake({
            requested: (200, {"Content-Type": "application/json"}, body),
        }))
        with self.assertRaises(JSONError) as ctx:
            client.get_engagement(11, product_id=7)
        self.assertIsNotNone(ctx.exception.response)
        self.assertEqual(ctx.exception.response.body, body)

    def test_non_finite_json_constants_are_rejected_for_detail_and_collection(self):
        cases = (
            ("https://dojo.example/api/v2/products/1/", b'{"id":1,"name":NaN}',
             lambda client: client.get_product(1)),
            ("https://dojo.example/api/v2/products/", b'{"count":1,"next":null,"results":[{"id":1,"score":Infinity}]}',
             lambda client: client.list_products()),
            ("https://dojo.example/api/v2/products/", b'{"count":1,"next":null,"results":[{"id":1,"score":-Infinity}]}',
             lambda client: client.list_products()),
        )
        for requested, body, operation in cases:
            with self.subTest(requested=requested, body=body):
                client = CEReadClient("https://dojo.example", Fake({
                    requested: (200, {"Content-Type": "application/json"}, body),
                }))
                with self.assertRaises(JSONError) as ctx:
                    operation(client)
                self.assertEqual(ctx.exception.response.body, body)

    def test_exponent_overflow_is_rejected_for_nested_detail_and_collection_json(self):
        cases = (
            ("https://dojo.example/api/v2/products/1/", b'{"id":1,"metadata":{"score":1e400}}',
             lambda client: client.get_product(1)),
            ("https://dojo.example/api/v2/products/", b'{"count":1,"next":null,"results":[{"id":1,"items":[1e400]}]}',
             lambda client: client.list_products()),
        )
        for requested, body, operation in cases:
            with self.subTest(requested=requested, body=body):
                client = CEReadClient("https://dojo.example", Fake({
                    requested: (200, {"Content-Type": "application/json"}, body),
                }))
                with self.assertRaises(JSONError) as ctx:
                    operation(client)
                self.assertIs(ctx.exception.response.body, body)

    def test_raw_response_rejects_non_string_header_keys_and_values_before_copy(self):
        for headers in ({1: "ok"}, {"Content-Type": ["application/json"]}):
            with self.subTest(headers=headers):
                with self.assertRaises(TypeError):
                    RawResponse(200, headers, b"{}", "https://dojo.example/")

    def test_raw_response_headers_are_string_snapshot(self):
        headers = {"Content-Type": "application/json"}
        raw = RawResponse(200, headers, b"{}", "https://dojo.example/")
        headers["X-Caller"] = "mutated"
        self.assertEqual(dict(raw.headers), {"Content-Type": "application/json"})

    def test_shape_error_preserves_exact_raw_response(self):
        requested = "https://dojo.example/api/v2/products/"
        raw = response({"count": 0, "next": None, "results": {}})
        client = CEReadClient("https://dojo.example", Fake({requested: raw}))
        with self.assertRaises(ShapeError) as ctx:
            client.list_products()
        self.assertEqual(ctx.exception.response.body, raw[2])

    def test_scope_error_preserves_exact_raw_response(self):
        requested = "https://dojo.example/api/v2/tests/8/"
        raw = response({"id": 8, "engagement": 3})
        client = CEReadClient("https://dojo.example", Fake({requested: raw}))
        with self.assertRaises(ScopeError) as ctx:
            client.get_test(8, engagement_id=4)
        self.assertEqual(ctx.exception.response.body, raw[2])

    def test_pagination_error_preserves_exact_raw_response(self):
        requested = "https://dojo.example/api/v2/products/"
        raw = response({"count": 1, "next": "https://evil.example/api/v2/products/", "results": [{"id": 1}]})
        client = CEReadClient("https://dojo.example", Fake({requested: raw}))
        with self.assertRaises(PaginationError) as ctx:
            client.list_products()
        self.assertEqual(ctx.exception.response.body, raw[2])

    def test_redirect_status_is_rejected_without_following(self):
        requested = "https://dojo.example/api/v2/products/"
        fake = Fake({requested: response({}, status=302, headers={"Location": "https://evil.example/"})})
        client = CEReadClient("https://dojo.example", fake)
        with self.assertRaises(HTTPError) as ctx:
            client.list_products()
        self.assertEqual(ctx.exception.response.status, 302)
        self.assertFalse(fake.calls[0][4])

    def test_transport_without_redirect_keyword_is_not_accepted(self):
        calls = []

        def follows(method, url, headers, timeout):
            calls.append((method, url, headers, timeout))
            return response({"count": 0, "next": None, "results": []})

        client = CEReadClient("https://dojo.example", follows, token="secret")
        with self.assertRaises(TransportError):
            client.list_products()
        self.assertEqual(calls, [])

    def test_pagination_stays_in_same_collection_and_configured_base_path(self):
        first = "https://dojo.example/dojo/api/v2/products/"
        escaped = "https://dojo.example/api/v2/products/"
        client = CEReadClient(
            "https://dojo.example/dojo", Fake({
                first: response({
                    "count": 1,
                    "next": escaped,
                    "results": [{"id": 1}],
                }),
            }),
        )
        with self.assertRaises(PaginationError):
            client.list_products()

    def test_pagination_cannot_switch_collections(self):
        first = "https://dojo.example/api/v2/products/"
        switched = "https://dojo.example/api/v2/engagements/"
        fake = Fake({first: response({
            "count": 1,
            "next": switched,
            "results": [{"id": 1}],
        })})
        client = CEReadClient("https://dojo.example", fake)
        with self.assertRaises(PaginationError):
            client.list_products()
        self.assertEqual(len(fake.calls), 1)

    def test_effective_redirect_url_is_rejected_and_preserved(self):
        requested = "https://dojo.example/api/v2/products/"
        effective = "https://evil.example/api/v2/products/"
        fake = Fake({requested: type("Response", (), {
            "status": 200,
            "headers": {},
            "body": b'{"count": 0, "next": null, "results": []}',
            "url": effective,
        })()})
        client = CEReadClient("https://dojo.example", fake)
        with self.assertRaises(TransportError) as ctx:
            client.list_products()
        self.assertEqual(ctx.exception.response.url, effective)

    def test_missing_or_invalid_parent_ids_are_typed_errors(self):
        client, _ = self.client({})
        with self.assertRaises(ShapeError):
            client.list_tests(engagement_id=0)
        with self.assertRaises(ShapeError):
            client.list_findings(test_id=None)

    def test_scope_is_checked_for_parent_chain(self):
        url = "https://dojo.example/api/v2/tests/8/"
        client, _ = self.client({url: response({"id": 8, "engagement": 3})})
        with self.assertRaises(ScopeError):
            client.get_test(8, engagement_id=4)

    def test_detail_parent_ids_are_validated_before_transport(self):
        client, fake = self.client({})
        with self.assertRaises(ShapeError):
            client.get_test(8, engagement_id=0)
        with self.assertRaises(ShapeError):
            client.get_finding(9, test_id=None)
        self.assertEqual(fake.calls, [])

    def test_cross_origin_next_is_rejected_before_request(self):
        first = "https://dojo.example/api/v2/products/"
        client, fake = self.client({first: response({"count": 1, "next": "https://evil.example/api/v2/products/", "results": [{"id": 1}]})})
        with self.assertRaises(PaginationError):
            client.list_products()
        self.assertEqual(len(fake.calls), 1)

    def test_next_cannot_change_fixed_collection_filter(self):
        first = "https://dojo.example/api/v2/findings/?test=7"
        changed = "https://dojo.example/api/v2/findings/?offset=1&test=8"
        client, fake = self.client({
            first: response({
                "count": 2,
                "next": changed,
                "results": [{"id": 1, "test": 7}],
            }),
        })
        with self.assertRaises(PaginationError):
            client.list_findings(test_id=7)
        self.assertEqual(len(fake.calls), 1)

    def test_duplicate_and_count_mismatch_are_rejected(self):
        first = "https://dojo.example/api/v2/products/"
        next_url = "https://dojo.example/api/v2/products/?offset=1"
        client, _ = self.client({
            first: response({"count": 2, "next": next_url, "results": [{"id": 1}]}),
            next_url: response({"count": 3, "next": None, "results": [{"id": 1}]})})
        with self.assertRaises(PaginationError):
            client.list_products()

    def test_transport_failure_does_not_expose_secret(self):
        def broken(*args):
            raise OSError("socket failed")
        client = CEReadClient("https://dojo.example", broken, token="secret")
        with self.assertRaises(TransportError) as ctx:
            client.get_product(1)
        self.assertNotIn("secret", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
