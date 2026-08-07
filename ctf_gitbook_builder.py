#!/usr/bin/env python3
"""
ir0nstone-style Cybersecurity Notes & CTF Writeup Builder
=========================================================
Aggregates writeups and notes across repositories into an ir0nstone-style
category-first & topic-driven GitBook structure.

Structure:
  Category (e.g. Binary Exploitation) -> Topic/Subcategory (e.g. Stack, Heap) -> Writeup/Guide
  + CTF Writeups Archive (Event -> Category -> Challenge)

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
        self.subcategory = "General"
        self.points = ""
        self.tags = []
        
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

        # Infer Subcategory/Topic
        if "subcategory" in self.frontmatter:
            self.subcategory = str(self.frontmatter["subcategory"]).strip('"\'')
        elif "topic" in self.frontmatter:
            self.subcategory = str(self.frontmatter["topic"]).strip('"\'')
        else:
            self.subcategory = self._infer_subcategory_from_path()

        # Normalize Event and Category
        self.event = self._clean_name(self.event)
        self.subcategory = self._clean_name(self.subcategory)
        
    def _parse_yaml_simple(self, fm_text: str):
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
        if len(parts) >= 3:
            return parts[0]
        return self.repo_name

    def _infer_category_from_path(self) -> str:
        path_str = str(self.rel_path).lower() + " " + self.repo_name.lower()
        if any(k in path_str for k in ["pwn", "binary", "exploit", "stack", "heap", "rop", "kernel"]):
            return "Binary Exploitation"
        elif any(k in path_str for k in ["rev", "reverse", "crackme", "ghidra", "gdb", "assembly"]):
            return "Reverse Engineering"
        elif any(k in path_str for k in ["web", "sqli", "xss", "ssti", "ssrf", "auth"]):
            return "Web Exploitation"
        elif any(k in path_str for k in ["crypto", "rsa", "aes", "ecc", "cipher"]):
            return "Cryptography"
        elif any(k in path_str for k in ["forensic", "stego", "memory", "pcap"]):
            return "Forensics"
        elif any(k in path_str for k in ["osint", "recon", "geo"]):
            return "OSINT"
        return "Misc & Case Studies"

    def _infer_subcategory_from_path(self) -> str:
        content_lower = (self.title + " " + str(self.rel_path)).lower()
        if "stack" in content_lower or "rop" in content_lower or "overflow" in content_lower:
            return "Stack"
        elif "heap" in content_lower or "uaf" in content_lower or "tcache" in content_lower:
            return "Heap"
        elif "fmt" in content_lower or "format" in content_lower:
            return "Format Strings"
        elif "kernel" in content_lower:
            return "Kernel"
        elif "assembly" in content_lower or "x86" in content_lower or "arm" in content_lower:
            return "Assembly"
        elif "sql" in content_lower:
            return "SQL Injection"
        elif "xss" in content_lower:
            return "XSS"
        elif "rsa" in content_lower:
            return "RSA"
        return "General"

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
        self.writeups: List[CTFWriteup] = []
        self.categories_cfg = self.config.get("categories", {})
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
        return raw_cat.title() if raw_cat else "Misc & Case Studies"

    def fetch_github_org_repos(self, org_name: str) -> List[str]:
        print(f"[+] Discovering repositories for GitHub organization: {org_name}...")
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
            except Exception:
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
        print(f"[+] Scanning {source_dir} (Source: {repo_name})...")
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'vendor', '.git', 'docs', 'temp_repos']]
            for file in files:
                if file.endswith('.md') and not file.lower().startswith('readme'):
                    file_path = Path(root) / file
                    writeup = CTFWriteup(file_path, repo_name, source_dir)
                    writeup.category = self.normalize_category(writeup.category)
                    self.writeups.append(writeup)

    def process_and_copy(self):
        """Copies markdown files into category-first ir0nstone directory structure."""
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        for w in self.writeups:
            cat_cfg = self.categories_cfg.get(w.category, {})
            cat_slug = cat_cfg.get("slug", self._slugify(w.category))
            subcat_slug = self._slugify(w.subcategory)
            file_slug = self._slugify(w.title) + ".md"

            dest_dir = self.output_dir / cat_slug / subcat_slug
            dest_dir.mkdir(parents=True, exist_ok=True)

            dest_file = dest_dir / file_slug
            w.target_rel_path = dest_file.relative_to(self.output_dir)

            # Process image links
            processed_body = self._process_assets(w, dest_dir)

            # Write file with metadata block
            header = f"# {w.title}\n\n"
            metadata_pills = f"**Category**: `{w.category}` | **Topic**: `{w.subcategory}` | **Source / Event**: `{w.event}`\n\n---\n\n"
            final_content = header + metadata_pills + processed_body

            with open(dest_file, 'w', encoding='utf-8') as f:
                f.write(final_content)

    def _process_assets(self, writeup: CTFWriteup, dest_dir: Path) -> str:
        content = writeup.body
        assets_dir = dest_dir / "assets"
        img_pattern = re.compile(r'!\[([^\]]*)\]\(([^)]+)\)')

        def replace_img(match):
            alt = match.group(1)
            raw_path = match.group(2).strip()
            parts = raw_path.split(' ', 1)
            img_src = parts[0].strip('"\'')
            title_part = f' "{parts[1]}"' if len(parts) > 1 else ''

            if img_src.startswith(('http://', 'https://', 'data:')):
                return match.group(0)

            src_img_path = (writeup.file_path.parent / img_src).resolve()
            if src_img_path.exists() and src_img_path.is_file():
                assets_dir.mkdir(parents=True, exist_ok=True)
                dest_img_name = f"{self._slugify(writeup.title)}_{src_img_path.name}"
                dest_img_path = assets_dir / dest_img_name
                shutil.copy2(src_img_path, dest_img_path)
                return f"![{alt}](assets/{dest_img_name}{title_part})"
            return match.group(0)

        return img_pattern.sub(replace_img, content)

    def generate_summary(self):
        """Generates ir0nstone-style SUMMARY.md with Category & Subtopic hierarchy."""
        print("[+] Generating ir0nstone-style GitBook SUMMARY.md...")
        summary_lines = [
            "# Table of Contents",
            "",
            "* [🏠 Home](README.md)",
            ""
        ]

        # Group writeups by Category -> Subcategory
        cat_map: Dict[str, Dict[str, List[CTFWriteup]]] = {}
        for w in self.writeups:
            if w.category not in cat_map:
                cat_map[w.category] = {}
            if w.subcategory not in cat_map[w.category]:
                cat_map[w.category][w.subcategory] = []
            cat_map[w.category][w.subcategory].append(w)

        # Iterate through Categories in defined config order
        for cat_name, cat_meta in self.categories_cfg.items():
            if cat_name not in cat_map:
                continue

            icon = cat_meta.get("icon", "📄")
            cat_slug = cat_meta.get("slug", self._slugify(cat_name))
            cat_readme = f"{cat_slug}/README.md"
            
            self._generate_category_readme(cat_name, cat_map[cat_name], cat_readme, icon)

            summary_lines.append(f"## {icon} {cat_name}")
            summary_lines.append(f"* [{cat_name} Overview]({cat_readme})")

            subcats = cat_map[cat_name]
            for subcat_name in sorted(subcats.keys()):
                subcat_slug = self._slugify(subcat_name)
                subcat_readme = f"{cat_slug}/{subcat_slug}/README.md"
                self._generate_subcat_readme(cat_name, subcat_name, subcats[subcat_name], subcat_readme, icon)

                summary_lines.append(f"  * [{subcat_name}]({subcat_readme})")
                for w in sorted(subcats[subcat_name], key=lambda x: x.title):
                    summary_lines.append(f"    * [{w.title}]({w.target_rel_path.as_posix()})")

            summary_lines.append("")

        # Add CTF Events Archive Section
        summary_lines.append("## 🏆 CTF Writeups Archive")
        events_map: Dict[str, List[CTFWriteup]] = {}
        for w in self.writeups:
            if w.event not in events_map:
                events_map[w.event] = []
            events_map[w.event].append(w)

        for event_name in sorted(events_map.keys()):
            event_slug = self._slugify(event_name)
            event_readme = f"events/{event_slug}/README.md"
            self._generate_event_archive_readme(event_name, events_map[event_name], event_readme)
            summary_lines.append(f"* [{event_name}]({event_readme})")

        summary_content = "\n".join(summary_lines)
        with open(self.output_dir / "SUMMARY.md", 'w', encoding='utf-8') as f:
            f.write(summary_content)

    def _generate_category_readme(self, cat_name: str, subcats: Dict[str, List[CTFWriteup]], rel_path: str, icon: str):
        full_path = self.output_dir / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        total_writeups = sum(len(w_list) for w_list in subcats.values())

        content = f"""# {icon} {cat_name}

Welcome to the **{cat_name}** section.

### 📊 Overview
- **Total Notes / Writeups**: `{total_writeups}`
- **Subtopics**: {", ".join([f"`{s}`" for s in subcats.keys()])}

---

### 🗂️ Topics & Guides

"""
        for subcat_name, w_list in subcats.items():
            subcat_slug = self._slugify(subcat_name)
            content += f"#### [{subcat_name}]({subcat_slug}/README.md)\n"
            for w in sorted(w_list, key=lambda x: x.title):
                content += f"- [{w.title}]({subcat_slug}/{self._slugify(w.title)}.md)\n"
            content += "\n"

        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def _generate_subcat_readme(self, cat_name: str, subcat_name: str, writeups: List[CTFWriteup], rel_path: str, icon: str):
        full_path = self.output_dir / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)

        content = f"""# {icon} {subcat_name} — {cat_name}

Topic notes and writeups under **{subcat_name}**.

### 📜 Articles & Writeups ({len(writeups)})

"""
        for w in sorted(writeups, key=lambda x: x.title):
            content += f"- [{w.title}]({self._slugify(w.title)}.md) *(Source: {w.event})*\n"

        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def _generate_event_archive_readme(self, event_name: str, writeups: List[CTFWriteup], rel_path: str):
        full_path = self.output_dir / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)

        content = f"""# 🏆 {event_name} Archive

CTF challenge writeups solved in **{event_name}**.

### 📜 Challenges Solved ({len(writeups)})

"""
        for w in sorted(writeups, key=lambda x: x.title):
            content += f"- [{w.title}](../../{w.target_rel_path.as_posix()}) — Category: `{w.category}`\n"

        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def generate_root_readme(self):
        """Generates ir0nstone-style homepage landing page README.md."""
        print("[+] Generating ir0nstone-style homepage README.md...")
        title = self.config.get("blog_title", "MoriartyPuth Labs - Cybersecurity Notes")
        description = self.config.get("blog_description", "")
        
        events_set = set(w.event for w in self.writeups)

        content = f"""# {title}

{description}

> Inspired by [ir0nstone's notes](https://ir0nstone.gitbook.io/notes).

---

### 🧭 Navigation & Sections

| Category | Description | Count |
| :--- | :--- | :--- |
"""
        cat_counts: Dict[str, int] = {}
        for w in self.writeups:
            cat_counts[w.category] = cat_counts.get(w.category, 0) + 1

        for cat_name, cat_meta in self.categories_cfg.items():
            count = cat_counts.get(cat_name, 0)
            if count == 0:
                continue
            icon = cat_meta.get("icon", "📄")
            cat_slug = cat_meta.get("slug", self._slugify(cat_name))
            content += f"| **{icon} [{cat_name}]({cat_slug}/README.md)** | Key concepts, writeups, and techniques | `{count}` |\n"

        content += f"""
---

### 📊 Quick Stats

- 🚩 **Total Writeups & Notes**: `{len(self.writeups)}`
- 🏆 **CTF Competitions Archived**: `{len(events_set)}`

---

*Maintained by [MoriartyPuth-Labs](https://github.com/MoriartyPuth-Labs).*
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

    print(f"[+] Total writeups discovered: {len(builder.writeups)}")
    if not builder.writeups:
        print("[!] No writeups found.")
        return

    # 2. Process, copy into ir0nstone layout, and generate SUMMARY.md and README.md
    builder.process_and_copy()
    builder.generate_summary()
    builder.generate_root_readme()
    
    print("[Success] ir0nstone-style GitBook project generated in 'docs/'!")

if __name__ == "__main__":
    main()
