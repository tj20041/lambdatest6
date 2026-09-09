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

        # Pre-pass: log every restricted key that is about to be purged
        for attr_name, attr_value in attributes.items():
            if attr_name.lower() in self.restricted_keys:
                logger.warning(f"Purging sensitive attribute: {attr_name}")

        # Rebuild the attributes dict in a single comprehension pass, excluding
        # any restricted PII keys.  This avoids mutating the dict while an
        # iterator is open on it (which caused RuntimeError in the original code).
        event_envelope["attributes"] = {
            k: v for k, v in attributes.items()
            if k.lower() not in self.restricted_keys
        }

        # Post-sanitization audit: confirm no restricted keys remain
        remaining_restricted = [
            k for k in event_envelope["attributes"]
            if k.lower() in self.restricted_keys
        ]
        if remaining_restricted:
            logger.error(
                f"BUG: restricted keys still present after scrub: {remaining_restricted}"
            )
        else:
            logger.info(
                f"Event {event_envelope.get('event_id')} sanitized successfully. "
                f"No restricted keys remain in attributes."
            )

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
    sanitized_envelope = pipeline.scrub_event_payload(simulated_event)

    logger.info("Sanitization complete. Event ready for downstream distribution.")
    return {"statusCode": 200, "cleaned_event": sanitized_envelope}

if __name__ == "__main__":
    lambda_handler({}, None)
