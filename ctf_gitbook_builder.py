#!/usr/bin/env python3
"""
CTF GitBook Aggregator & Builder
================================
Aggregates CTF writeups from multiple Git repositories or local directories into a 
unified, GitBook-compatible repository organized by:
  Event -> Category -> Challenge

Author: MoriartyPuth Labs
"""

import os
import sys
import re
import json
import shutil
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

CATEGORY_ICONS = {
    "Web": "🌐",
    "Pwn": "⚔️",
    "Reverse Engineering": "🔍",
    "Cryptography": "🔐",
    "Forensics": "🕵️",
    "OSINT": "🧭",
    "Misc": "🎲",
    "Hardware": "⚡",
    "Cloud": "☁️",
    "Blockchain": "⛓️",
    "AI / ML": "🤖"
}

DEFAULT_ICON = "📄"

class CTFWriteup:
    def __init__(self, file_path: Path, repo_name: str, base_source_dir: Path):
        self.file_path = file_path
        self.repo_name = repo_name
        self.base_source_dir = base_source_dir
        self.rel_path = file_path.relative_to(base_source_dir)
        
        self.raw_content = ""
        self.frontmatter: Dict[str, Any] = {}
        self.body = ""
        self.title = ""
        self.event = ""
        self.category = ""
        self.points = ""
        self.tags = []
        self.assets: List[Path] = []
        
        self._parse()

    def _parse(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.raw_content = f.read()
        except Exception as e:
            print(f"[-] Error reading {self.file_path}: {e}")
            return

        # Extract frontmatter if present
        fm_match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)$', self.raw_content, re.DOTALL)
        if fm_match:
            fm_text = fm_match.group(1)
            self.body = fm_match.group(2)
            self._parse_yaml_simple(fm_text)
        else:
            self.body = self.raw_content

        # Fallbacks for Title
        if "title" in self.frontmatter:
            self.title = str(self.frontmatter["title"]).strip('"\'')
        else:
            h1_match = re.search(r'^#\s+(.+)$', self.body, re.MULTILINE)
            if h1_match:
                self.title = h1_match.group(1).strip()
            else:
                self.title = self.file_path.stem.replace('_', ' ').replace('-', ' ').title()

        # Fallbacks for Event
        if "event" in self.frontmatter:
            self.event = str(self.frontmatter["event"]).strip('"\'')
        elif "ctf" in self.frontmatter:
            self.event = str(self.frontmatter["ctf"]).strip('"\'')
        else:
            self.event = self._infer_event_from_path()

        # Fallbacks for Category
        if "category" in self.frontmatter:
            self.category = str(self.frontmatter["category"]).strip('"\'')
        else:
            self.category = self._infer_category_from_path()

        # Normalize Event and Category
        self.event = self._clean_name(self.event)
        
    def _parse_yaml_simple(self, fm_text: str):
        """Simple YAML parser for frontmatter metadata without heavy external dependencies."""
        for line in fm_text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                key, val = line.split(':', 1)
                key = key.strip().lower()
                val = val.strip().strip('"\'')
                if val.startswith('[') and val.endswith(']'):
                    val = [x.strip().strip('"\'') for x in val[1:-1].split(',')]
                self.frontmatter[key] = val

    def _infer_event_from_path(self) -> str:
        parts = self.rel_path.parts
        if len(parts) >= 3: # e.g. Event/Category/Writeup.md
            return parts[0]
        elif len(parts) == 2:
            return self.repo_name
        return self.repo_name

    def _infer_category_from_path(self) -> str:
        parts = [p.lower() for p in self.rel_path.parts]
        for part in parts[:-1]: # exclude filename
            for cat_key in ["web", "pwn", "crypto", "rev", "reverse", "forensics", "osint", "stego", "misc", "hardware", "cloud", "blockchain", "ai"]:
                if cat_key in part:
                    return part
        return "misc"

    @staticmethod
    def _clean_name(name: str) -> str:
        name = re.sub(r'^[0-9]+[_\-\.]', '', name)
        name = name.replace('_', ' ').replace('-', ' ').strip()
        return name.title() if name else "General"


class GitBookBuilder:
    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.output_dir = Path(self.config.get("output_dir", "docs"))
        self.events_dir = self.output_dir / "events"
        self.writeups: List[CTFWriteup] = []
        self.cat_aliases = self.config.get("category_aliases", {})

    def _load_config(self) -> dict:
        if self.config_path.exists():
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def normalize_category(self, raw_cat: str) -> str:
        clean = raw_cat.lower().strip()
        for key, canonical in self.cat_aliases.items():
            if key in clean:
                return canonical
        return raw_cat.title() if raw_cat else "Misc"

    def fetch_github_org_repos(self, org_name: str) -> List[str]:
        """Fetch list of public repository clone URLs for a GitHub organization."""
        print(f"[+] Discovering public repositories for GitHub organization: {org_name}...")
        urls = []
        page = 1
        headers = {"User-Agent": "CTF-GitBook-Builder"}
        
        token = os.getenv("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"

        while True:
            api_url = f"https://api.github.com/orgs/{org_name}/repos?per_page=100&page={page}"
            req = urllib.request.Request(api_url, headers=headers)
            try:
                with urllib.request.urlopen(req) as resp:
                    if resp.status != 200:
                        break
                    data = json.loads(resp.read().decode('utf-8'))
                    if not data:
                        break
                    for repo in data:
                        name = repo.get("name", "")
                        if name not in self.config.get("exclude_repos", []):
                            urls.append(repo.get("clone_url"))
                    page += 1
            except Exception as e:
                print(f"[!] Note: Org discovery returned {e}. Trying user repos endpoint...")
                # Fallback to user repos if org endpoint fails
                api_url = f"https://api.github.com/users/{org_name}/repos?per_page=100&page={page}"
                req = urllib.request.Request(api_url, headers=headers)
                try:
                    with urllib.request.urlopen(req) as resp:
                        data = json.loads(resp.read().decode('utf-8'))
                        if not data:
                            break
                        for repo in data:
                            name = repo.get("name", "")
                            if name not in self.config.get("exclude_repos", []):
                                urls.append(repo.get("clone_url"))
                        break
                except Exception as ex:
                    print(f"[-] Could not fetch repos for {org_name}: {ex}")
                    break
        print(f"[+] Found {len(urls)} repositories in {org_name}.")
        return urls

    def scan_directory(self, source_dir: Path, repo_name: str):
        """Scans a local directory for markdown writeup files."""
        print(f"[+] Scanning {source_dir} (Source: {repo_name})...")
        for root, dirs, files in os.walk(source_dir):
            # Skip hidden dirs and .git
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'vendor', '.git']]
            for file in files:
                if file.endswith('.md') and not file.lower().startswith('readme'):
                    file_path = Path(root) / file
                    writeup = CTFWriteup(file_path, repo_name, source_dir)
                    writeup.category = self.normalize_category(writeup.category)
                    self.writeups.append(writeup)

    def process_and_copy(self):
        """Copies markdown files and relative image assets into GitBook output directory."""
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        for w in self.writeups:
            event_slug = self._slugify(w.event)
            cat_slug = self._slugify(w.category)
            file_slug = self._slugify(w.title) + ".md"

            dest_dir = self.events_dir / event_slug / cat_slug
            dest_dir.mkdir(parents=True, exist_ok=True)

            dest_file = dest_dir / file_slug
            w.target_rel_path = dest_file.relative_to(self.output_dir)

            # Process image links inside body
            processed_body = self._process_assets(w, dest_dir)

            # Write file with frontmatter clean header
            header = f"# {w.title}\n\n"
            metadata_pills = f"**Event**: `{w.event}` | **Category**: `{w.category}`"
            if w.points:
                metadata_pills += f" | **Points**: `{w.points}`"
            metadata_pills += "\n\n---\n\n"

            final_content = header + metadata_pills + processed_body

            with open(dest_file, 'w', encoding='utf-8') as f:
                f.write(final_content)

    def _process_assets(self, writeup: CTFWriteup, dest_dir: Path) -> str:
        """Finds image references, copies image files, and updates paths relative to dest_dir."""
        content = writeup.body
        assets_dir = dest_dir / "assets"

        # Regex for markdown image links: ![alt](path "optional title")
        img_pattern = re.compile(r'!\[([^\]]*)\]\(([^)]+)\)')

        def replace_img(match):
            alt = match.group(1)
            raw_path = match.group(2).strip()
            
            # Split title if present
            parts = raw_path.split(' ', 1)
            img_src = parts[0].strip('"\'')
            title_part = f' "{parts[1]}"' if len(parts) > 1 else ''

            if img_src.startswith(('http://', 'https://', 'data:')):
                return match.group(0)

            # Resolve local image source
            src_img_path = (writeup.file_path.parent / img_src).resolve()
            if src_img_path.exists() and src_img_path.is_file():
                assets_dir.mkdir(parents=True, exist_ok=True)
                dest_img_name = f"{self._slugify(writeup.title)}_{src_img_path.name}"
                dest_img_path = assets_dir / dest_img_name
                shutil.copy2(src_img_path, dest_img_path)
                
                # New relative path for GitBook
                rel_img_path = f"assets/{dest_img_name}"
                return f"![{alt}]({rel_img_path}{title_part})"
            
            return match.group(0)

        return img_pattern.sub(replace_img, content)

    def generate_summary(self):
        """Generates GitBook's SUMMARY.md table of contents."""
        print("[+] Generating GitBook SUMMARY.md...")
        summary_lines = [
            "# Table of Contents",
            "",
            "* [🏠 Home](README.md)",
            ""
        ]

        # Group writeups by Event -> Category
        events_map: Dict[str, Dict[str, List[CTFWriteup]]] = {}
        for w in self.writeups:
            if w.event not in events_map:
                events_map[w.event] = {}
            if w.category not in events_map[w.event]:
                events_map[w.event][w.category] = []
            events_map[w.event][w.category].append(w)

        # Sort events alphabetically
        for event_name in sorted(events_map.keys()):
            event_slug = self._slugify(event_name)
            event_readme = f"events/{event_slug}/README.md"
            self._generate_event_readme(event_name, events_map[event_name], event_readme)

            summary_lines.append(f"## 🏆 {event_name}")
            summary_lines.append(f"* [{event_name} Overview]({event_readme})")

            categories_map = events_map[event_name]
            # Order categories based on config order
            ordered_cats = sorted(categories_map.keys(), key=lambda c: self.config.get("category_order", []).index(c) if c in self.config.get("category_order", []) else 99)

            for cat_name in ordered_cats:
                icon = CATEGORY_ICONS.get(cat_name, DEFAULT_ICON)
                cat_slug = self._slugify(cat_name)
                cat_readme = f"events/{event_slug}/{cat_slug}/README.md"
                self._generate_category_readme(event_name, cat_name, categories_map[cat_name], cat_readme)

                summary_lines.append(f"  * {icon} {cat_name}")
                summary_lines.append(f"    * [{cat_name} Index]({cat_readme})")

                # Sort challenges inside category by title
                for w in sorted(categories_map[cat_name], key=lambda x: x.title):
                    summary_lines.append(f"    * [{w.title}]({w.target_rel_path.as_posix()})")

            summary_lines.append("")

        summary_content = "\n".join(summary_lines)
        with open(self.output_dir / "SUMMARY.md", 'w', encoding='utf-8') as f:
            f.write(summary_content)

    def _generate_event_readme(self, event_name: str, categories: Dict[str, List[CTFWriteup]], rel_path: str):
        full_path = self.output_dir / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)

        total_challenges = sum(len(w_list) for w_list in categories.values())
        cat_breakdown = ", ".join([f"`{c}` ({len(w_list)})" for c, w_list in categories.items()])

        content = f"""# 🏆 {event_name}

Welcome to the writeups archive for **{event_name}**.

### 📊 Overview & Stats
- **Total Challenges Solved**: `{total_challenges}`
- **Categories Covered**: {cat_breakdown}

### 🗂️ Categories

"""
        for cat_name, w_list in categories.items():
            icon = CATEGORY_ICONS.get(cat_name, DEFAULT_ICON)
            cat_slug = self._slugify(cat_name)
            content += f"#### {icon} [{cat_name}]({cat_slug}/README.md)\n"
            for w in sorted(w_list, key=lambda x: x.title):
                content += f"- [{w.title}]({cat_slug}/{self._slugify(w.title)}.md)\n"
            content += "\n"

        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def _generate_category_readme(self, event_name: str, cat_name: str, writeups: List[CTFWriteup], rel_path: str):
        full_path = self.output_dir / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        icon = CATEGORY_ICONS.get(cat_name, DEFAULT_ICON)

        content = f"""# {icon} {cat_name} - {event_name}

All writeups under **{cat_name}** for **{event_name}**.

### 📜 Challenges List ({len(writeups)})

"""
        for w in sorted(writeups, key=lambda x: x.title):
            content += f"- [{w.title}]({self._slugify(w.title)}.md)\n"

        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def generate_root_readme(self):
        """Generates GitBook homepage landing page README.md."""
        print("[+] Generating homepage README.md...")
        title = self.config.get("blog_title", "Cybersecurity & CTF Writeups")
        description = self.config.get("blog_description", "")
        
        events_set = set(w.event for w in self.writeups)
        categories_set = set(w.category for w in self.writeups)

        content = f"""# {title}

{description}

---

### 📊 Blog Statistics

| Metric | Count |
| :--- | :--- |
| 🚩 **Total Writeups** | `{len(self.writeups)}` |
| 🏆 **CTF Events** | `{len(events_set)}` |
| 🗂️ **Categories** | `{len(categories_set)}` |

---

### 🗂️ Categories Breakdown

"""
        # Group stats by category
        cat_counts: Dict[str, int] = {}
        for w in self.writeups:
            cat_counts[w.category] = cat_counts.get(w.category, 0) + 1

        for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
            icon = CATEGORY_ICONS.get(cat, DEFAULT_ICON)
            content += f"- **{icon} {cat}**: `{count}` writeups\n"

        content += """
---

### 🏆 CTF Events Archive

"""
        event_counts: Dict[str, int] = {}
        for w in self.writeups:
            event_counts[w.event] = event_counts.get(w.event, 0) + 1

        for event, count in sorted(event_counts.items()):
            event_slug = self._slugify(event)
            content += f"- [{event}](events/{event_slug}/README.md) — `{count}` challenges solved\n"

        content += """
---

*Automated & generated with ❤️ by [MoriartyPuth-Labs CTF GitBook Builder](https://github.com/MoriartyPuth-Labs).*
"""
        with open(self.output_dir / "README.md", 'w', encoding='utf-8') as f:
            f.write(content)

    @staticmethod
    def _slugify(text: str) -> str:
        text = text.lower().strip()
        text = re.sub(r'[^\w\s-]', '', text)
        text = re.sub(r'[\s_-]+', '-', text)
        return text.strip('-') or "item"


def main():
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    builder = GitBookBuilder(config_file)

    # 1. Discover repos from GitHub Orgs
    for org in builder.config.get("github_orgs", []):
        urls = builder.fetch_github_org_repos(org)
        for url in urls:
            repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
            tmp_clone_dir = Path("temp_repos") / repo_name
            if not tmp_clone_dir.exists():
                print(f"[+] Cloning {url}...")
                os.system(f"git clone --depth 1 {url} {tmp_clone_dir}")
            builder.scan_directory(tmp_clone_dir, repo_name)

    # 2. Scan explicit local sources (for testing or local repos)
    for local_path in builder.config.get("local_sources", []):
        p = Path(local_path)
        if p.exists():
            builder.scan_directory(p, p.name)

    print(f"[+] Total writeups discovered: {len(builder.writeups)}")
    if not builder.writeups:
        print("[!] No writeups found. Creating demo directory structure...")
        # Create demo writeup if no writeups exist yet
        demo_dir = Path("temp_repos/demo-ctf-2024/web")
        demo_dir.mkdir(parents=True, exist_ok=True)
        with open(demo_dir / "sql-injection-boss.md", "w") as f:
            f.write("""---
title: "SQL Injection Boss"
event: "DEFCON CTF 2024"
category: "Web"
points: 500
---

# SQL Injection Boss Writeup

## Challenge Description
Bypass the admin login portal using advanced SQL injection techniques.

## Solution
Input `' OR 1=1--` into the username field.
""")
        builder.scan_directory(Path("temp_repos/demo-ctf-2024"), "demo-ctf-2024")

    # 3. Process, copy, and generate SUMMARY.md and README.md
    builder.process_and_copy()
    builder.generate_summary()
    builder.generate_root_readme()
    
    print("[Success] GitBook project generated in output directory 'docs/'!")

if __name__ == "__main__":
    main()
