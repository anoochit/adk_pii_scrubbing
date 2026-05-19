from google.adk.agents.llm_agent import Agent
from google.adk.tools.tool_context import ToolContext
from google.adk.tools.base_tool import BaseTool
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import json

# Initialize once at startup
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Map each Presidio entity type to a redaction label.
# Full list: https://microsoft.github.io/presidio/supported_entities/
PII_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "LOCATION",
    "IP_ADDRESS",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "US_PASSPORT",
    "DATE_TIME",
    "NRP",
    "MEDICAL_LICENSE",
    "URL",
]

# Each entity gets its own placeholder in the anonymized output
OPERATORS = {
    entity: OperatorConfig("replace", {"new_value": f"[REDACTED_{entity}]"})
    for entity in PII_ENTITIES
}


def scrub_string(text: str, language: str = "en") -> str:
    """Detect and anonymize PII in a plain string using Presidio."""
    results = analyzer.analyze(
        text=text,
        entities=PII_ENTITIES,
        language=language,
    )
    if not results:
        return text
    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=OPERATORS,
    )
    return anonymized.text


def scrub_data(obj, language: str = "en"):
    """Recursively scrub PII from any JSON-like structure."""
    if isinstance(obj, dict):
        return {k: scrub_data(v, language) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_data(item, language) for item in obj]
    if isinstance(obj, str):
        return scrub_string(obj, language)
    return obj


# --- Callback ---


def pii_scrub_callback(
    tool: BaseTool,
    args: dict,
    tool_context: ToolContext,
    tool_response: str,  # ← plain str, not dict
) -> str | None:
    try:
        parsed = json.loads(tool_response)
        scrubbed = scrub_data(parsed)
        return json.dumps(scrubbed)
    except (json.JSONDecodeError, TypeError):
        return scrub_string(str(tool_response))


# --- Tool ---


def get_employees():
    "show employees data"
    data = {
        "status": "success",
        "items": [
            {
                "id": 1,
                "name": "John Doe",
                "email": "john@inter.co",
                "phone": "0891234567",
            },
            {
                "id": 2,
                "name": "Jane Doe",
                "email": "jane@inter.co",
                "phone": "0891234567",
            },
        ],
    }
    return json.dumps(data)


# --- Agent ---

root_agent = Agent(
    model="gemini-2.5-flash",
    name="root_agent",
    description="A helpful assistant for user questions.",
    instruction="Answer user questions to the best of your knowledge",
    tools=[get_employees],
    after_tool_callback=pii_scrub_callback,
)
