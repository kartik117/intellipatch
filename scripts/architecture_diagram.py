"""Regenerates .github/assets/architecture.png.

Not part of the app -- a one-off documentation tool. Run with:
    pip install diagrams && python scripts/architecture_diagram.py
(requires graphviz: `brew install graphviz` / `apt install graphviz`)
"""

from diagrams import Diagram, Edge
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.client import Client
from diagrams.onprem.database import PostgreSQL
from diagrams.programming.language import Python

graph_attr = {"fontsize": "14", "bgcolor": "white", "pad": "0.4", "nodesep": "0.7", "ranksep": "1.0"}

with Diagram(
    "IntelliPatch Architecture",
    filename=".github/assets/architecture",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
):
    image = Client("Docker image\n(registry)")
    trivy = Python("trivy\n(real CVE scan)")
    ranker = Python("ranking model\n(RandomForest)")
    remediation = Python("remediation\n(deterministic +\noptional LLM)")
    postgres = PostgreSQL("postgres\n(scans, findings)")
    api = Python("api\n(FastAPI)")
    client = Client("client")
    ci = GithubActions("CI/CD pipeline")
    gate = Python("gate.py\n(CLI)")

    image >> Edge(label="scan") >> trivy >> Edge(label="real findings") >> ranker
    ranker >> Edge(label="ranked findings") >> postgres
    postgres >> Edge(style="dotted") >> api
    client >> Edge(label="POST /scans,\nGET /findings/{id}/remediation") >> api
    api >> Edge(style="dotted") >> remediation

    ci >> Edge(label="invokes") >> gate
    gate >> Edge(label="scan + rank\n(no fix + high\npriority -> exit 1)") >> trivy
