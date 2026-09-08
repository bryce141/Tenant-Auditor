import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # macOS ControlCenter (AirPlay Receiver) holds port 5000 by default, so the
    # port is overridable rather than hard-coded.
    port = int(os.getenv("PORT", "5001"))
    app.run(debug=True, port=port)
