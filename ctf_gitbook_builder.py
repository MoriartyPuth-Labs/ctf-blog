#!/usr/bin/env python3
"""
MoriartyPuth Labs GitBook Builder
=================================
Structure:
  1. About Me
  2. Cybersecurity Notes (Templates for manual notes: Recon, Pwn, Web, Rev, Crypto, Forensics, OSINT, Cloud)
  3. CTF Writeups (6 CTF Repositories: D3CTF, CNCC, Crackmes, VulnHub, LYKN CTF, Bronco CTF)

Author: MoriartyPuth Labs
"""

import os
import sys
import re
import json
import shutil
from pathlib import Path
from typing import Dict, List, Any

CATEGORY_ICONS = {
    "web": "🌐",
    "pwn": "⚔️",
    "reverse": "🔍",
    "rev": "🔍",
    "crypto": "🔐",
    "forensics": "🕵️",
    "osint": "🧭",
    "misc": "🎲"
}

class CTFWriteup:
    def __init__(self, file_path: Path, repo_slug: str, base_source_dir: Path):
        self.file_path = file_path
        self.repo_slug = repo_slug
        self.base_source_dir = base_source_dir
        self.rel_path = file_path.relative_to(base_source_dir)
        
        self.raw_content = ""
        self.body = ""
        self.title = ""
        self.category = "misc"
        
        self._parse()

    def _parse(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.raw_content = f.read()
        except Exception as e:
            print(f"[-] Error reading {self.file_path}: {e}")
            return

        # Extract title from markdown H1 or frontmatter
        h1_match = re.search(r'^#\s+(.+)$', self.raw_content, re.MULTILINE)
        if h1_match:
            self.title = h1_match.group(1).strip()
        else:
            self.title = self.file_path.stem.replace('_', ' ').replace('-', ' ').title()

        # Infer category from folder structure
        parts = [p.lower() for p in self.rel_path.parts[:-1]]
        for p in parts:
            for cat_key in ["web", "pwn", "crypto", "reverse", "rev", "forensics", "osint", "misc"]:
                if cat_key in p:
                    self.category = "reverse" if cat_key == "rev" else cat_key
                    break

        self.body = self.raw_content

class GitBookBuilder:
    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.output_dir = Path(self.config.get("output_dir", "docs"))

    def _load_config(self) -> dict:
        if self.config_path.exists():
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def setup_notes_templates(self):
        """Generates template README.md files for Cybersecurity Notes sections."""
        print("[+] Setting up Cybersecurity Notes section templates...")
        notes_dir = self.output_dir / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)

        # Overview README
        overview_content = """# 📚 Cybersecurity Notes

Welcome to my personal cybersecurity research notes and reference guides.

### 🗂️ Categories
"""
        for cat in self.config.get("notes_categories", []):
            cat_dir = notes_dir / cat["slug"]
            cat_dir.mkdir(parents=True, exist_ok=True)
            readme_path = cat_dir / "README.md"
            
            if not readme_path.exists():
                cat_template = f"""# {cat['icon']} {cat['name']}

Welcome to the **{cat['name']}** notes section.

### 📝 Topics & Guides

Write your notes and techniques here...
- [Sample Guide](guide.md)
"""
                with open(readme_path, 'w', encoding='utf-8') as f:
                    f.write(cat_template)

            overview_content += f"- **{cat['icon']} [{cat['name']}]({cat['slug']}/README.md)**\n"

        with open(notes_dir / "README.md", 'w', encoding='utf-8') as f:
            f.write(overview_content)

    def process_ctf_repos(self) -> Dict[str, Dict[str, List[CTFWriteup]]]:
        """Clones the 6 CTF repos, parses writeups, and places them in docs/ctf-writeups/."""
        print("[+] Processing 6 CTF writeup repositories...")
        ctf_writeups_dir = self.output_dir / "ctf-writeups"
        
        # We clean ctf-writeups directory before generating
        if ctf_writeups_dir.exists():
            shutil.rmtree(ctf_writeups_dir)
        ctf_writeups_dir.mkdir(parents=True, exist_ok=True)

        results: Dict[str, Dict[str, List[CTFWriteup]]] = {}

        for repo_info in self.config.get("ctf_repos", []):
            name = repo_info["name"]
            slug = repo_info["slug"]
            url = repo_info["repo_url"]
            
            tmp_clone_dir = Path("temp_repos") / slug
            if not tmp_clone_dir.exists():
                print(f"[+] Cloning {name} ({url})...")
                os.system(f"git clone --depth 1 {url} {tmp_clone_dir}")

            # Scan writeups
            results[slug] = {}
            for root, dirs, files in os.walk(tmp_clone_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['.git', 'node_modules']]
                for file in files:
                    if file.endswith('.md') and not file.lower().startswith('readme'):
                        fpath = Path(root) / file
                        w = CTFWriteup(fpath, slug, tmp_clone_dir)
                        
                        cat = w.category
                        if cat not in results[slug]:
                            results[slug][cat] = []
                        results[slug][cat].append(w)

                        # Copy to docs/ctf-writeups/{slug}/{cat}/{filename}
                        dest_dir = ctf_writeups_dir / slug / cat
                        dest_dir.mkdir(parents=True, exist_ok=True)
                        dest_file = dest_dir / file
                        
                        # Update target rel path
                        w.target_rel_path = dest_file.relative_to(self.output_dir)

                        # Copy writeup
                        with open(dest_file, 'w', encoding='utf-8') as f:
                            f.write(w.body)

            # Create event README.md
            event_readme = ctf_writeups_dir / slug / "README.md"
            event_readme.parent.mkdir(parents=True, exist_ok=True)
            total = sum(len(wl) for wl in results[slug].values())

            event_content = f"# 🏆 {name}\n\nAll challenge writeups from **{name}**.\n\n### Total Challenges Solved: `{total}`\n\n"
            for cat, wlist in results[slug].items():
                icon = CATEGORY_ICONS.get(cat, "📄")
                event_content += f"#### {icon} {cat.title()}\n"
                for w in sorted(wlist, key=lambda x: x.title):
                    rel = w.target_rel_path.relative_to(Path("ctf-writeups") / slug).as_posix()
                    event_content += f"- [{w.title}]({rel})\n"
                event_content += "\n"

            with open(event_readme, 'w', encoding='utf-8') as f:
                f.write(event_content)

        return results

    def generate_summary(self, ctf_data: Dict[str, Dict[str, List[CTFWriteup]]]):
        """Generates clean SUMMARY.md with About, Notes, and CTF Writeups sections."""
        print("[+] Generating SUMMARY.md...")
        lines = [
            "# Table of Contents",
            "",
            "* [🏠 Home](README.md)",
            "* [👤 About Me](about/README.md)",
            "",
            "## 📚 Cybersecurity Notes",
            "* [Notes Overview](notes/README.md)"
        ]

        for cat in self.config.get("notes_categories", []):
            lines.append(f"  * [{cat['icon']} {cat['name']}](notes/{cat['slug']}/README.md)")

        lines.append("")
        lines.append("## 🏆 CTF Writeups")
        lines.append("* [CTF Writeups Overview](ctf-writeups/README.md)")

        # Write CTF Overview README
        overview_path = self.output_dir / "ctf-writeups" / "README.md"
        overview_content = "# 🏆 CTF Writeups Archive\n\nCurated collection of CTF challenge writeups.\n\n"

        for repo_info in self.config.get("ctf_repos", []):
            name = repo_info["name"]
            slug = repo_info["slug"]
            lines.append(f"  * [{name}](ctf-writeups/{slug}/README.md)")

            cats = ctf_data.get(slug, {})
            for cat in sorted(cats.keys()):
                icon = CATEGORY_ICONS.get(cat, "📄")
                lines.append(f"    * {icon} {cat.title()}")
                for w in sorted(cats[cat], key=lambda x: x.title):
                    lines.append(f"      * [{w.title}]({w.target_rel_path.as_posix()})")

            overview_content += f"- **[{name}]({slug}/README.md)** — `{sum(len(l) for l in cats.values())}` challenges solved\n"

        with open(overview_path, 'w', encoding='utf-8') as f:
            f.write(overview_content)

        with open(self.output_dir / "SUMMARY.md", 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

    def generate_root_readme(self):
        """Generates homepage README.md."""
        print("[+] Generating root README.md...")
        content = """# MoriartyPuth Labs - Cybersecurity Blog & Writeups

Welcome to my cybersecurity blog!

---

### 🗂️ Navigation

1. **[👤 About Me](about/README.md)** — Bio, certifications, and research focus.
2. **[📚 Cybersecurity Notes](notes/README.md)** — Core notes on Recon, Pwn, Web, Rev, Crypto, Forensics, OSINT & Cloud.
3. **[🏆 CTF Writeups](ctf-writeups/README.md)** — Detailed challenge writeups across CTF events.

---

*Maintained by [MoriartyPuth-Labs](https://github.com/MoriartyPuth-Labs).*
"""
        with open(self.output_dir / "README.md", 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    builder = GitBookBuilder("config.json")
    builder.setup_notes_templates()
    ctf_data = builder.process_ctf_repos()
    builder.generate_summary(ctf_data)
    builder.generate_root_readme()
    print("[Success] GitBook generated successfully!")

if __name__ == "__main__":
    main()
