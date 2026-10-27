import unittest
import uuid
import hashlib
import json

from uvm.engine.ce_read_client import CEReadClient, ScopeError
from uvm.engine.context import (
    CEContextObservationV1,
    CEContextRegistrationV1,
    CEDeploymentMismatchError,
    ConfiguredCEDeploymentV1,
    verify_ce_context,
)


class Fake:
    def __init__(self, responses):
        self.responses = responses

    def __call__(self, method, url, headers, timeout, *, follow_redirects):
        return self.responses[url]


def raw(value):
    return 200, {"Content-Type": "application/json"}, json.dumps(value, separators=(",", ":")).encode()


class CEContextRegistrationTestCase(unittest.TestCase):
    def _registration(self, **overrides):
        values = dict(
            schema_version=1,
            registration_id=str(uuid.uuid4()),
            deployment_key="dev",
            context_key="qualys/account-a/web",
            product_id=7,
            engagement_id=11,
        )
        values.update(overrides)
        return CEContextRegistrationV1(**values)

    def test_registration_is_immutable_and_test_binding_is_once_only(self):
        registration = self._registration()
        bound = registration.bind_test(19)
        self.assertIsNone(registration.test_id)
        self.assertEqual(bound.test_id, 19)
        with self.assertRaises(ValueError):
            bound.bind_test(20)

    def test_positive_ce_ids_and_non_empty_identity_are_required(self):
        for field, value in (("product_id", 0), ("engagement_id", -1), ("test_id", 0)):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self._registration(**{field: value})
        with self.assertRaises(ValueError):
            self._registration(context_key="")


class CEContextVerificationTestCase(unittest.TestCase):
    base = "https://dojo.example"

    def _verify(self, *, product=None, engagement=None, test=None, test_id=13, base=None):
        product = product or {"id": 7, "name": "web"}
        engagement = engagement or {"id": 11, "product": 7}
        responses = {
            f"{self.base}/api/v2/products/7/": raw(product),
            f"{self.base}/api/v2/engagements/11/": raw(engagement),
        }
        if test_id is not None:
            responses[f"{self.base}/api/v2/tests/{test_id}/"] = raw(test or {"id": test_id, "engagement": 11})
        client = CEReadClient(base or self.base, Fake(responses))
        configured = ConfiguredCEDeploymentV1(1, "dev-eu", "HTTPS://DOJO.EXAMPLE/", "3.3.100")
        return verify_ce_context(configured, client, context_key="web", product_id=7,
                                 engagement_id=11, test_id=test_id)

    def test_correct_chain_returns_optional_test_candidate_and_exact_digests(self):
        registration, observation = self._verify()
        self.assertEqual((registration.deployment_key, registration.test_id), ("dev-eu", 13))
        self.assertEqual([item.resource for item in observation.responses], ["product", "engagement", "test"])
        for item in observation.responses:
            self.assertEqual(item.body, item.response.body)
            self.assertEqual(item.body_sha256, hashlib.sha256(item.body).hexdigest())
        self.assertFalse(observation.trusted_runtime_config)
        self.assertFalse(observation.durable_evidence)
        self.assertFalse(observation.live_provenance)

    def test_first_import_can_omit_test(self):
        registration, observation = self._verify(test_id=None)
        self.assertIsNone(registration.test_id)
        self.assertIsNone(observation.test_id)
        self.assertEqual(len(observation.responses), 2)

    def test_wrong_product_engagement_and_test_fail_closed(self):
        with self.assertRaises(ScopeError):
            self._verify(product={"id": 8})
        with self.assertRaises(ScopeError):
            self._verify(engagement={"id": 11, "product": 8})
        with self.assertRaises(ScopeError):
            self._verify(test={"id": 13, "engagement": 12})

    def test_configured_client_url_mismatch_is_rejected_before_get(self):
        with self.assertRaises(CEDeploymentMismatchError):
            self._verify(base="https://other.example")

    def test_observation_and_configuration_are_immutable(self):
        registration, observation = self._verify()
        with self.assertRaises(AttributeError):
            registration.deployment_key = "other"
        with self.assertRaises(AttributeError):
            observation.responses = ()
        with self.assertRaises(TypeError):
            observation.responses[0].response.headers["X"] = "changed"
        self.assertEqual(observation.responses[0].body_sha256,
                         hashlib.sha256(observation.responses[0].body).hexdigest())

    def test_observation_defensively_copies_response_sequence_and_headers(self):
        registration, observation = self._verify()
        supplied = list(observation.responses)
        headers = dict(supplied[0].response.headers)
        rebuilt = CEContextObservationV1(
            schema_version=1,
            deployment_key=observation.deployment_key,
            ce_base_url=observation.ce_base_url,
            ce_release=observation.ce_release,
            product_id=observation.product_id,
            engagement_id=observation.engagement_id,
            test_id=observation.test_id,
            responses=supplied,
        )
        supplied.clear()
        headers["X-Mutated"] = "caller"
        supplied.append(observation.responses[0])
        self.assertEqual(len(rebuilt.responses), 3)
        self.assertNotIn("X-Mutated", rebuilt.responses[0].response.headers)
        self.assertEqual(rebuilt.responses[0].body, observation.responses[0].body)


if __name__ == "__main__":
    unittest.main()
