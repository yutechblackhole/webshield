import json
from scanner import perform_scan

def handler(request):
    """Vercel-compatible serverless handler that runs the scanner.perform_scan function.
    Expects a JSON body like {"url": "https://example.com"} or a query `?url=...`.
    """
    try:
        # Try to get JSON body k(works with Vercel request object)
        data = None
        try:
            data = request.get_json() if hasattr(request, "get_json") else None
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
