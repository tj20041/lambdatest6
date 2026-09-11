import json
import logging
import sys
from typing import Any, Dict, List

logger = logging.getLogger("event_fanout_dispatcher")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logging.Formatter("[%(levelname)s] %(asctime)s - %(message)s"))
logger.handlers = [stream_handler]

RESTRICTED_PII_FIELDS = ["ssn", "credit_card_number", "passport_id", "security_pin"]


class EventSanitizationPipeline:
    def __init__(self, restricted_keys: List[str]):
        self.restricted_keys = set(restricted_keys)

    def scrub_event_payload(self, event_envelope: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"Auditing event {event_envelope.get('event_id')} for restricted attributes...")

        attributes = event_envelope.get("attributes", {})

        # FIXED: Do not mutate the dictionary while iterating over it.
        # Rebuild the attributes dict via a comprehension over a static snapshot
        # of keys, logging a warning for each purged field, instead of calling
        # `del attributes[attr_name]` inside a `for attr_name in attributes:` loop
        # (which raised RuntimeError: dictionary changed size during iteration).
        sanitized_attributes: Dict[str, Any] = {}
        for attr_name in list(attributes.keys()):
            if attr_name.lower() in self.restricted_keys:
                logger.warning(f"Purging sensitive attribute: {attr_name}")
                continue
            sanitized_attributes[attr_name] = attributes[attr_name]

        event_envelope["attributes"] = sanitized_attributes

        return event_envelope


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("Executing event sanitation and multicast fan-out handler...")

    simulated_event = {
        "event_id": "EVT-8921-X",
        "tenant_id": "ORG-ALPHA",
        "timestamp": 1718001000,
        "attributes": {
            "account_id": "ACC-1002",
            "ssn": "000-12-3456",
            "email": "user@example.com",
            "security_pin": "9921",
            "status": "VERIFIED"
        }
    }

    pipeline = EventSanitizationPipeline(restricted_keys=RESTRICTED_PII_FIELDS)

    try:
        sanitized_envelope = pipeline.scrub_event_payload(simulated_event)
    except Exception as exc:  # noqa: BLE001 - defensive guard around sanitization
        logger.error(f"Failed to sanitize event payload: {exc}", exc_info=True)
        return {"statusCode": 500, "error": str(exc)}

    logger.info("Sanitization complete. Event ready for downstream distribution.")
    return {"statusCode": 200, "cleaned_event": sanitized_envelope}


if __name__ == "__main__":
    lambda_handler({}, None)

    # Regression check: multiple restricted keys present simultaneously must not
    # raise RuntimeError (dictionary changed size during iteration).
    multi_key_pipeline = EventSanitizationPipeline(restricted_keys=RESTRICTED_PII_FIELDS)
    multi_key_event = {
        "event_id": "EVT-REGRESSION-1",
        "attributes": {
            "ssn": "111-22-3333",
            "credit_card_number": "4111111111111111",
            "passport_id": "P1234567",
            "security_pin": "0000",
            "account_id": "ACC-9999",
            "status": "VERIFIED"
        }
    }
    result = multi_key_pipeline.scrub_event_payload(multi_key_event)
    logger.info(f"Regression check result: {result}")
