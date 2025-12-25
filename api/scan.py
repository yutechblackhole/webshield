import json
from code import perform_scan

def handler(request):
    """Vercel-compatible serverless handler that runs the scanner.perform_scan function.
    Expects a JSON body like {"url": "https://example.com"} or a query `?url=...`.
    """
    try:
        # Try to get JSON body
        data = None
        try:
            if hasattr(request, "get_json"):
                data = request.get_json()
        except Exception:
            data = None

        url = None
        if data:
            url = data.get("url") or data.get("target_url")

        # Fallback to query string
        if not url and hasattr(request, "args"):
            url = request.args.get("url")

        if not url:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "No URL provided"})
            }

        results = perform_scan(url)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"results": results, "url": url})
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }
