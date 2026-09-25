"""Build the standalone offline file using only Python's standard library."""
from pathlib import Path

root = Path(__file__).resolve().parent
html = (root / 'template.html').read_text()
html = html.replace('/* ENGINE */', (root / 'engine.js').read_text())
html = html.replace('/* INTERFACE */', (root / 'interface.js').read_text())
target = root.parent / 'Terrapin_Demonstrator.html'
target.write_text(html)
print(target)



#builder