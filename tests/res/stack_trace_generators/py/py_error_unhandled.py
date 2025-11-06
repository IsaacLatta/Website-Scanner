def process_request(request):
    if not isinstance(request, dict):
        raise ValueError("Request must be a dictionary")

def handle_client():
    # Simulate receiving bad input from network
    request = "GET /index.html"
    process_request(request)

if __name__ == "__main__":
    handle_client()
