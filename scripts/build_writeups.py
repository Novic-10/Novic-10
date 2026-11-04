import os
import re
import sys
import glob
import shutil
import argparse
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from google.genai import types

def parse_args():
    parser = argparse.ArgumentParser(
        description="Build HTML CTF writeups from Markdown drafts using Gemini API."
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Specify a single Markdown draft file to process (e.g., drafts/BEC-ky.md or BEC-ky.md)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate execution without calling API or writing output files"
    )
    return parser.parse_args()

# Parse command-line arguments
args = parse_args()
DRY_RUN = args.dry_run

# Load environment variables from .env file locally
load_dotenv()

# Fetch API key from environment
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("GEMINI_API_KEY environment variable is not set!")

# Initialize Google GenAI Client
client = genai.Client(api_key=api_key)

# Define input/output directory structures
DRAFTS_DIR = Path("drafts")
WRITEUPS_DIR = Path("writeups")
DRAFT_IMAGES = DRAFTS_DIR / "images"
WRITEUP_IMAGES = WRITEUPS_DIR / "images"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} | Oliver Hersee</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-slate-950 text-slate-200 font-sans antialiased selection:bg-cyan-500 selection:text-slate-950">
    <main class="max-w-4xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <a href="../index.html#writeups" class="inline-flex items-center gap-2 text-slate-400 hover:text-cyan-400 text-sm font-mono mb-8 transition-colors">
            <i class="fa-solid fa-arrow-left text-xs"></i> Back to Portfolio
        </a>
        <article class="prose prose-invert max-w-none space-y-6">
            {content}
        </article>
    </main>
</body>
</html>
"""

SYSTEM_PROMPT = """
You are an expert Cybersecurity Technical Writer. Convert the provided raw CTF Markdown notes into a concise, executive-ready CTF writeup in HTML styled with Tailwind CSS and FontAwesome icons, matching the exact top header layout of InkSec.io writeups.

STRICT STYLING & COLOR SCHEME:
- Outer Container / Backgrounds: slate-950 page background, slate-900 inner containers, slate-800 borders/accents.
- Text Colors: slate-100 headers, slate-200 body, slate-400 secondary/meta text.
- Accent & Code Colors: cyan-400 for primary accents, cyan-300 font-mono for inline code/paths/hashes.
- Font Setup: Clean sans-serif for main body, font-mono for badges, tags, commands, logs, and buttons.

REQUIRED INKSEC HEADER STRUCTURE (Top of Writeup):
1. Platform Breadcrumb Tagline:
   - Text format: `// {PLATFORM} · WRITEUP` in font-mono text-xs text-slate-400 uppercase tracking-widest. (Infer platform from tags like #Blue Team Labs Online, #TryHackMe, #Cyberdefenders, or default to `#CTF`).

2. CTF Title:
   - Clean, bold H1 header (`text-3xl sm:text-4xl font-bold text-slate-100 tracking-tight my-3`). Do NOT place inside a boxed container.

3. Metadata Pill Badges (Single Horizontal Line):
   - Render a flex-wrap container (`flex flex-wrap gap-2 my-4 font-mono text-xs uppercase`).
   - Badge 1 (Platform): `bg-cyan-950 text-cyan-400 border border-cyan-800 px-3 py-1 rounded`. This is what platform hosts the CTF e.g (Blue Team Labs Online, TryHackMe etc...)
   - Badge 3 (Category): `bg-slate-800 text-slate-300 border border-slate-700 px-3 py-1 rounded`. Derive category from hashtags e.g (Incident Response, Digital Forensics, Reverse Engineering etc...)
   - Badge 4 (Difficulty): `bg-slate-800 text-slate-300 border border-slate-700 px-3 py-1 rounded`. Pull difficulty from hashtags
   - Badges 5-6 (Top 3 Tools used): Extract up to 3 core tools mentioned in the notes (e.g., SPLUNK, SYSMON, ROBOCOPY) as `bg-slate-800/80 text-slate-400 border border-slate-700/60 px-3 py-1 rounded`.

4. Action Button Bar:
   - Render a flex-wrap gap container (`flex flex-wrap items-center gap-3 mt-6 mb-8 font-mono text-xs`):
   - Button 1 ("Back to Portfolio"): 
     `<a href="../index.html#writeups" class="inline-flex items-center gap-2 border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 px-4 py-2 rounded transition-all">← BACK TO PORTFOLIO</a>`
   - Button 2 ("Proof of Completion"): 
     Extract the primary completion/badge screenshot or external proof link from the raw .md file notes (e.g., `images/...png` or URL).
     `<a href="{extracted_proof_path_or_image}" target="_blank" class="inline-flex items-center gap-2 border border-pink-500/40 text-pink-400 hover:bg-pink-500/10 px-4 py-2 rounded transition-all">PROOF OF COMPLETION →</a>`

TABLE FORMATTING & OVERFLOW RULES (CRITICAL):
1. EVERY HTML table MUST be wrapped in a container div with overflow handling:
   <div class="overflow-x-auto my-6 rounded-lg border border-slate-800 shadow-lg">
     <table class="w-full text-left border-collapse text-sm">...</table>
   </div>
2. Enable Word Wrapping on Long Artifacts:
   - All `<td>` elements and `<code>` blocks inside table cells MUST include `break-all` or `break-words` class (e.g., `<td class="py-3 px-4 break-words font-mono text-xs">` or `<code class="break-all font-mono text-cyan-300">`).
   - This prevents long registry keys, file paths, command lines, or hashes from forcing table columns off-screen or getting cut off.
3. Table Headers & Rows:
   - `<thead>` rows should use `bg-slate-800/80 text-slate-300 text-xs uppercase tracking-wider font-mono`.
   - `<tbody>` rows should alternate with `border-b border-slate-800/60 hover:bg-slate-800/40 transition-colors`.

DOCUMENT SECTIONS:
1. Executive Summary & Overview (Crisp, high-density attack chain overview).
2. Asset Information & Indicators of Compromise (IOC) Matrix (Styled HTML tables following the overflow rules above). The Asset Information table will have Columns for hostname and Summary. The Indicators of Compromise table must only have Type, Summary and MITRE ATT&CK Code. Ensure all of the MITRE ATT&CK codes are filled in for each column accurately.
3. Step-by-Step Investigation Workflow (Terminal code blocks with 1-line descriptions).
4. Question & Answer Solutions (Concise, bold font-mono answers with 1-line reasoning).
5. Key Takeaways & Security Insights.

CRITICAL INLINE IMAGE HANDLING RULES:
1. Preserve EVERY Markdown image tag `![alt text](images/filename.png)` exactly where it appears in the input flow.
2. Convert each image reference into the responsive HTML block:
   <figure class="my-6">
     <img src="images/{filename}" alt="{alt text}" class="rounded-lg border border-slate-700/80 w-full shadow-md hover:border-slate-600 transition-all" />
     <figcaption class="text-xs text-center text-slate-400 mt-2 font-mono">{alt text}</figcaption>
   </figure>
3. Do NOT omit, rename, move, or hallucinate image relative paths.

OUTPUT FORMAT:
Return ONLY the raw HTML inner fragment inside `<div class="max-w-5xl mx-auto px-4 py-8">...</div>`. Do NOT wrap in markdown code blocks like ```html.
"""

def sync_images():
    """Recursively copies all image assets from drafts/images/ to writeups/images/."""
    if DRAFT_IMAGES.exists():
        if DRY_RUN:
            print(f"[DRY-RUN] Would sync images from {DRAFT_IMAGES} -> {WRITEUP_IMAGES}")
        else:
            WRITEUP_IMAGES.mkdir(parents=True, exist_ok=True)
            shutil.copytree(DRAFT_IMAGES, WRITEUP_IMAGES, dirs_exist_ok=True)
            print(f"[+] Synced images from {DRAFT_IMAGES} -> {WRITEUP_IMAGES}")
    else:
        print("[!] No drafts/images directory found. Skipping asset sync.")

def extract_title(markdown_text, fallback_filename):
    """Extracts title metadata from YAML frontmatter first, then H1 header, defaulting to formatted filename."""
    # 1. Check YAML frontmatter first (title: "...")
    title_match = re.search(r'^title:\s*["\']?(.*?)["\']?$', markdown_text, re.MULTILINE)
    if title_match and title_match.group(1).strip():
        return title_match.group(1).strip()

    # 2. Check for the first H1 header (# Title)
    h1_match = re.search(r"^#\s+(.+)$", markdown_text, re.MULTILINE)
    if h1_match and h1_match.group(1).strip():
        return h1_match.group(1).strip()

    # 3. Fallback to formatted filename
    return fallback_filename.replace("-", " ").title()

def clean_gemini_output(raw_text):
    """Strips Markdown code fences if returned by the LLM."""
    cleaned = re.sub(r"^```html\s*", "", raw_text, flags=re.MULTILINE)
    cleaned = re.sub(r"^```\s*$", "", cleaned, flags=re.MULTILINE)
    return cleaned.strip()

def resolve_target_files():
    """Determines whether to return all markdown drafts or a specific single target file."""
    if args.file:
        target_path = Path(args.file)
        # Handle cases where user passes "BEC-ky.md" vs "drafts/BEC-ky.md"
        if not target_path.exists() and (DRAFTS_DIR / target_path.name).exists():
            target_path = DRAFTS_DIR / target_path.name
        
        if not target_path.exists():
            print(f"[!] Error: Specified file '{args.file}' does not exist.")
            sys.exit(1)
            
        return [str(target_path)]
    
    return glob.glob(str(DRAFTS_DIR / "*.md"))

def process_drafts():
    if DRY_RUN:
        print("[DRY-RUN MODE ACTIVE] No API calls will be made, and no files will be written.\n")

    if not DRY_RUN:
        WRITEUPS_DIR.mkdir(parents=True, exist_ok=True)
    
    sync_images()

    draft_files = resolve_target_files()
    if not draft_files:
        print("[!] No markdown draft files found.")
        return
    
    for draft_path in draft_files:
        filename = Path(draft_path).stem
        output_path = WRITEUPS_DIR / f"{filename}.html"
        
        with open(draft_path, "r", encoding="utf-8") as f:
            raw_notes = f.read()
            
        print(f"Processing draft: {Path(draft_path).name} ...")
        page_title = extract_title(raw_notes, filename)
        
        if DRY_RUN:
            print(f"[DRY-RUN] Parsed Title: '{page_title}'")
            print(f"[DRY-RUN] Target output: {output_path}")
            print(f"[DRY-RUN] Skipped API generation for {Path(draft_path).name}\n")
            continue

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"Raw Notes:\n{raw_notes}",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.2,
            ),
        )
        
        html_content = clean_gemini_output(response.text)
        
        full_html = HTML_TEMPLATE.format(
            title=page_title,
            content=html_content
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_html)
            
        print(f"[✔] Successfully generated {output_path}")

if __name__ == "__main__":
    process_drafts()