"""Build one notebook per requirement from the definitions, then execute them so outputs are saved.

Usage: python build_notebooks.py [req_number ...]   (no arguments builds all 25)
"""
import re
import sys
from pathlib import Path

import nbformat
from nbclient import NotebookClient
from nbformat.v4 import new_code_cell, new_markdown_cell, new_notebook

from nb_defs_a import REQS_A
from nb_defs_b import REQS_B
from nb_defs_c import REQS_C

HERE = Path(__file__).parent
OUT = HERE / "notebooks"
OUT.mkdir(exist_ok=True)
REQS = {**REQS_A, **REQS_B, **REQS_C}


def build(number: int, req: dict) -> Path:
    cells = [
        new_markdown_cell(f"# Requirement {number}: {req['title']}\n\n> {req['text']}"),
        new_markdown_cell(f"**Covered by:** {req['covered']}\n\n**How it is fulfilled:** {req['how']}"),
        new_code_cell('import sys\nsys.path.insert(0, "..")'),
    ]
    cells += [new_code_cell(code) for code in req["cells"]]
    cells.append(new_markdown_cell(f"**Caveat:** {req['caveat']}"))
    notebook = new_notebook(cells=cells)
    notebook.metadata["kernelspec"] = {"name": "contoso-sandbox", "display_name": "Python (contoso-sandbox)", "language": "python"}
    slug = re.sub(r"[^a-z0-9]+", "_", req["title"].lower()).strip("_")
    path = OUT / f"{number:02d}_{slug}.ipynb"
    NotebookClient(notebook, timeout=600, kernel_name="contoso-sandbox", resources={"metadata": {"path": str(OUT)}}).execute()
    scrub(notebook)
    nbformat.write(notebook, path)
    return path


def scrub(notebook) -> None:
    """Replace live Azure names in saved outputs with placeholders."""
    from common import ADMIN_OID, ORCH_OID, RESOURCE_GROUP, SANDBOX_GROUP, SUBSCRIPTION, TENANT
    replacements = {
        SUBSCRIPTION: "<subscription-id>", RESOURCE_GROUP: "<resource-group>", SANDBOX_GROUP: "<sandbox-group>",
        TENANT: "<tenant-id>", ADMIN_OID: "<admin-object-id>", ORCH_OID: "<orchestrator-object-id>",
    }

    def clean(text: str) -> str:
        for live, placeholder in replacements.items():
            text = text.replace(live, placeholder)
        return text

    for cell in notebook.cells:
        for output in cell.get("outputs", []):
            for key in ("text", "evalue"):
                if key in output:
                    output[key] = clean(output[key])
            if "traceback" in output:
                output["traceback"] = [clean(line) for line in output["traceback"]]
            if "data" in output and "text/plain" in output["data"]:
                output["data"]["text/plain"] = clean(output["data"]["text/plain"])


if __name__ == "__main__":
    wanted = [int(a) for a in sys.argv[1:]] or sorted(REQS)
    failed = []
    for number in wanted:
        try:
            print("built", build(number, REQS[number]).name, flush=True)
        except Exception as err:
            failed.append(number)
            print(f"FAILED {number}: {str(err)[-600:]}", flush=True)
    print("failed:", failed or "none")
