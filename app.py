"""Esper — AI Attack Path Analysis Platform.

Phase 1: Multi-agent LangGraph pipeline with Security Knowledge Graph.
Phase 2: Database persistence, PDF reports, historical comparison.
"""

from flask import Flask

from api.routes import routes
from database.database import init_db

app = Flask(__name__)

# Register the API Blueprint
app.register_blueprint(routes)

# Ensure the database is created on startup
init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
