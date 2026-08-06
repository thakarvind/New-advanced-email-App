import argparse
import json
import os
import sys

try:
    from anthropic import Anthropic
except ImportError:  # pragma: no cover - fallback for environments without anthropic
    Anthropic = None


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def local_summary(data):
    if isinstance(data, dict):
        keys = list(data.keys())
        if not keys:
            return "JSON object is empty."
        return f"JSON object with keys: {', '.join(keys[:10])}{'...' if len(keys) > 10 else ''}"
    if isinstance(data, list):
        return f"JSON array with {len(data)} item(s)."
    return f"JSON value of type: {type(data).__name__}"


def main():
    parser = argparse.ArgumentParser(description="Send a JSON file to Claude for analysis")
    parser.add_argument("json_file", help="Path to the JSON file to analyze")
    parser.add_argument(
        "--prompt",
        default="Summarize this JSON and highlight the most important fields.",
        help="Prompt to send to Claude",
    )
    args = parser.parse_args()

    try:
        data = load_json(args.json_file)
    except FileNotFoundError:
        print(f"File not found: {args.json_file}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON in {args.json_file}: {exc}")
        sys.exit(1)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or Anthropic is None:
        print("ANTHROPIC_API_KEY not set or anthropic SDK is unavailable; running offline fallback.")
        print("\nLocal summary:")
        print(local_summary(data))
        print("\nPretty JSON:")
        print(json.dumps(data, indent=2))
        return

    client = Anthropic(api_key=api_key)
    payload = json.dumps(data, indent=2)

    response = client.messages.create(
        model="claude-3-5-sonnet-latest",
        max_tokens=1000,
        messages=[
            {
                "role": "user",
                "content": f"{args.prompt}\n\nJSON CONTENT:\n{payload}",
            }
        ],
    )

    print(response.content[0].text)


if __name__ == "__main__":
    main()
