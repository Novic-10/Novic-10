import os
import re
import sys
import glob
import shutil
import hashlib
import json
import base64
import mimetypes
import argparse
from pathlib import Path
from dotenv import load_dotenv
import frontmatter
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from google import genai
from google.genai import types

def parse_args():
    parser = argparse.ArgumentParser(
        description="Build HTML CTF writeups from Markdown drafts using Gemini API with AES-256 encryption."
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Specify a single Markdown draft file to process (e.g., drafts/Awesome.md)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate execution without calling API or writing output files"
    )
    parser.add_argument(
        "--drafts",
        type=str,
        default="drafts",
        help="Path to drafts directory (default: drafts)"
    )
    parser.add_argument(
        "--writeups",
        type=str,
        default="writeups",
        help="Path to writeups output directory (default: writeups)"
    )
    return parser.parse_args()

args = parse_args()
DRY_RUN = args.dry_run

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError("GEMINI_API_KEY environment variable is not set!")

client = genai.Client(api_key=api_key)

DRAFTS_DIR = Path(args.drafts)
WRITEUPS_DIR = Path(args.writeups)
DRAFT_IMAGES = DRAFTS_DIR / "images"
WRITEUP_IMAGES = WRITEUPS_DIR / "images"

# Standard Template for Unlocked (Retired) Writeups
UNLOCKED_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="ctf-title" content="{title}">
    <meta name="ctf-status" content="{status}">
    <meta name="ctf-pass-hash" content="{pass_hash}">
    <meta name="ctf-platform" content="{platform}">
    <meta name="ctf-difficulty" content="{difficulty}">
    <meta name="ctf-category" content="{category}">
    <meta name="ctf-description" content="{description}">
    <meta name="ctf-tags" content="{tags}">
    <title>{title}</title>
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

# AES-256 Self-Decrypting Template for Active (Locked) Writeups
LOCKED_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="ctf-title" content="{title}">
    <meta name="ctf-status" content="{status}">
    <meta name="ctf-pass-hash" content="{pass_hash}">
    <meta name="ctf-platform" content="{platform}">
    <meta name="ctf-difficulty" content="{difficulty}">
    <meta name="ctf-category" content="{category}">
    <meta name="ctf-description" content="{description}">
    <meta name="ctf-tags" content="{tags}">
    <title>{title}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-slate-950 text-slate-200 font-sans antialiased selection:bg-cyan-500 selection:text-slate-950 min-h-screen flex items-center justify-center">

    <!-- Encrypted Content Container (Hidden by default) -->
    <div id="decrypted-wrapper" class="hidden w-full max-w-4xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <a href="../index.html#writeups" class="inline-flex items-center gap-2 text-slate-400 hover:text-cyan-400 text-sm font-mono mb-8 transition-colors">
            <i class="fa-solid fa-arrow-left text-xs"></i> Back to Portfolio
        </a>
        <article id="decrypted-content" class="prose prose-invert max-w-none space-y-6">
        </article>
    </div>

    <!-- Password Prompt Card -->
    <div id="unlock-card" class="bg-[#0B1120] border border-cyan-800/60 rounded-2xl max-w-md w-full p-8 shadow-2xl">
        <div class="text-center mb-6">
            <div class="w-12 h-12 bg-amber-950/40 border border-amber-800/60 rounded-full flex items-center justify-center mx-auto mb-3">
                <i class="fas fa-lock text-amber-400 text-lg"></i>
            </div>
            <h2 class="text-xl font-bold font-sans text-cyan-400">{title}</h2>
            <p class="text-xs font-mono text-slate-400 mt-1">Password protected per Platform Guidelines - Password available on recruiter request</p>
        </div>

        <form id="decrypt-form" class="space-y-4">
            <div>
                <label for="page-password" class="block font-mono text-xs text-cyan-600/90 mb-2 uppercase">Enter Passcode to Decrypt</label>
                <input type="password" id="page-password" placeholder="••••••••" required autofocus
                       class="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 font-mono text-cyan-400 focus:outline-none focus:border-cyan-400 text-center tracking-widest">
            </div>

            <div id="decrypt-error" class="hidden font-mono text-xs text-rose-400 bg-rose-950/30 border border-rose-800/60 p-2.5 rounded-lg text-center">
                <i class="fas fa-exclamation-triangle mr-1"></i> Decryption Failed: Invalid Passcode
            </div>

            <button type="submit" class="w-full py-3 rounded-xl font-mono text-sm font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-all flex items-center justify-center gap-2">
                <i class="fas fa-key text-xs"></i> Decrypt Writeup
            </button>
        </form>
    </div>

    <!-- Encrypted Payload Store -->
    <script id="encrypted-payload" type="application/json">
        {ciphertext_json}
    </script>

    <script>
        document.getElementById('decrypt-form').addEventListener('submit', function(e) {{
            e.preventDefault();
            const pass = document.getElementById('page-password').value.trim();
            const payloadRaw = document.getElementById('encrypted-payload').textContent;
            const payload = JSON.parse(payloadRaw);
            const errorBox = document.getElementById('decrypt-error');

            try {{
                // Derive 256-bit Key from password via SHA-256
                const key = CryptoJS.SHA256(pass);
                const iv = CryptoJS.enc.Hex.parse(payload.iv);

                // Decrypt AES-256-CBC
                const decrypted = CryptoJS.AES.decrypt(payload.ciphertext, key, {{
                    iv: iv,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                }});

                const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);

                if (!decryptedText) {{
                    throw new Error("Invalid decryption output");
                }}

                // Successfully decrypted: Inject content into page
                document.getElementById('unlock-card').classList.add('hidden');
                document.body.classList.remove('min-h-screen', 'flex', 'items-center', 'justify-center');
                
                const wrapper = document.getElementById('decrypted-wrapper');
                document.getElementById('decrypted-content').innerHTML = decryptedText;
                wrapper.classList.remove('hidden');

            }} catch (err) {{
                errorBox.classList.remove('hidden');
                document.getElementById('page-password').select();
            }}
        }});
    </script>
</body>
</html>
"""

SYSTEM_PROMPT = """
You are an expert Cybersecurity Technical Writer. Convert the provided raw CTF Markdown notes into a concise, executive-ready CTF writeup in HTML styled with Tailwind CSS and FontAwesome icons, matching the exact visual benchmarks of InkSec.io writeups.

STRICT COLOR & FONTS:
- Backgrounds: slate-950 base page background (`bg-[#060A12]`), slate-900 card containers (`bg-[#0B1120]`).
- Borders: `border-slate-800/80` or `border-cyan-900/40`.
- Main Headers (H1, H2): Clean sans-serif, bold `text-slate-100` (`text-2xl sm:text-3xl font-bold tracking-tight mb-4 mt-8`).
- Highlights & Inline Code: Hostnames, binaries, usernames, registry paths, and script names MUST be wrapped in `font-mono text-cyan-400 font-semibold` (e.g. <code class="font-mono text-cyan-400 bg-cyan-950/40 px-1.5 py-0.5 rounded text-xs">DEV-WKS-01</code>).

REQUIRED INKSEC HEADER STRUCTURE (Top of Writeup):
1. Breadcrumb Tagline:
   - Format: `<p class="font-mono text-xs text-slate-500 uppercase tracking-widest mb-2">// {PLATFORM} · WRITEUP</p>`
2. Main H1 Title:
   - Format: `<h1 class="text-4xl sm:text-5xl font-bold text-slate-100 tracking-tight mb-4">{TITLE}</h1>`
   - Use strictly the literal title provided in the Raw Notes header without altering, expanding, or appending colon subtitles (e.g. use "Deep Freeze", NOT "DeepFreeze: S3 Data Exfiltration Analysis").
3. Metadata Pill Badges (Single Line):
   - Wrap in `<div class="flex flex-wrap gap-2 mb-6 font-mono text-xs font-semibold uppercase">`
   - Platform Badge: `<span class="bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 px-3 py-1 rounded">BLUE TEAM LABS ONLINE</span>`
   - Metadata Badges: `<span class="bg-slate-900 text-slate-400 border border-slate-800 px-3 py-1 rounded">EASY</span>`, `<span class="bg-slate-900 text-slate-400 border border-slate-800 px-3 py-1 rounded">SPLUNK</span>`, etc.
4. Action Buttons (Pill Bar):
   - Wrap in `<div class="flex flex-wrap items-center gap-3 my-6 font-mono text-xs">`
   - Back Button:
     `<a href="../index.html#writeups" class="inline-flex items-center gap-2 bg-[#092b38] border border-cyan-800 text-cyan-400 hover:bg-cyan-900/50 px-4 py-2 rounded-lg transition-all"><i class="fa-solid fa-arrow-left text-xs"></i> BACK TO PORTFOLIO</a>`
  

DOCUMENT SECTIONS & EXACT HTML COMPONENT LAYOUT:

1. Executive Summary & Overview:
   - Paragraphs styled with `text-slate-300 text-sm sm:text-base leading-relaxed space-y-4 mb-8 font-sans`.
   - Bold key assets and binaries using `text-cyan-400 font-mono text-xs font-semibold`.

2. Asset Information Table:
   - Heading: `<h2 class="text-2xl font-bold text-slate-100 mb-4 font-sans">Asset Information</h2>`
   - Table wrapper: `<div class="overflow-x-auto my-6 rounded-xl border border-slate-800/80 bg-[#0B1120] shadow-xl">`
   - Table: `<table class="w-full text-left border-collapse text-xs font-mono">`
   - Table Header (`<thead>`): `<tr class="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase tracking-wider"><th class="py-3 px-4">HOSTNAME</th><th class="py-3 px-4">SUMMARY</th></tr>`
   - Table Rows (`<tbody>`): `<tr class="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors"><td class="py-3 px-4 text-cyan-400 font-semibold break-all">...</td><td class="py-3 px-4 text-slate-300 break-words font-sans">...</td></tr>`


3. Question & Answer Solutions (CARD-BASED FORMAT):
   - Heading: `<h2 class="text-2xl font-bold text-slate-100 mb-6 font-sans">Question & Answer Solutions</h2>`
   - CRITICAL REQUIREMENT: EVERY SINGLE Question & Answer pair MUST be wrapped in its own individual dark card container `<div class="bg-[#0B1120] border border-slate-800/80 rounded-xl p-6 mb-4 shadow-xl space-y-3">`.
   - Inside Question Card Structure:
     a) Question Text: `<p class="text-slate-200 text-sm font-sans font-medium">1. What was the username...?</p>`
     b) Extracted Answer: `<p class="text-cyan-400 font-mono text-base font-bold tracking-wide break-all">Answer_Value_Here</p>`
     c) Reasoning: `<p class="text-slate-400 text-xs font-sans">Reasoning: Filtered for <code class="font-mono text-cyan-400">dev_harry</code> ARN...</p>`
     d) Embedded Images inside Q&A (if present): 
        <figure class="mt-4">
          <img src="images/{filename}" alt="{alt text}" class="rounded-lg border border-slate-700/80 w-full shadow-md" />
          <figcaption class="text-xs text-center text-slate-500 mt-2 font-mono">{alt text}</figcaption>
        </figure>

4. Key Takeaways & Security Insights:
   - Heading: `<h2 class="text-2xl font-bold text-slate-100 mb-4 font-sans">Key Takeaways & Security Insights</h2>`
   - List Container: `<ul class="space-y-4 text-sm text-slate-300 font-sans my-4">`
   - Bullet items: `<li class="flex items-start gap-2"><span class="text-cyan-400 mt-1">•</span><div><strong class="text-cyan-400 font-semibold font-mono">Title Here:</strong> Body takeaway explanation text...</div></li>`

CRITICAL INLINE IMAGE HANDLING RULES:
1. Preserve EVERY Markdown image tag `![alt text](images/filename.png)` exactly where it appears in the input flow.
2. Convert each image reference into the responsive HTML block:
   <figure class="my-6">
     <img src="images/{filename}" alt="{alt text}" class="rounded-lg border border-slate-700/80 w-full shadow-md hover:border-slate-600 transition-all" />
     <figcaption class="text-xs text-center text-slate-400 mt-2 font-mono">{alt text}</figcaption>
   </figure>

OUTPUT FORMAT:
Return ONLY the raw HTML inner fragment inside `<div class="max-w-5xl mx-auto px-4 py-8">...</div>`. Do NOT wrap in markdown code blocks like ```html.
"""

def hash_password(password: str) -> str:
    return hashlib.sha256(password.strip().encode('utf-8')).hexdigest()

def encrypt_html_content(html_content: str, password: str) -> str:
    """Encrypts HTML content using AES-256-CBC and returns JSON with IV and Ciphertext."""
    key = hashlib.sha256(password.strip().encode('utf-8')).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    padded_data = pad(html_content.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    
    payload = {
        "iv": iv.hex(),
        "ciphertext": base64.b64encode(encrypted_bytes).decode('utf-8')
    }
    return json.dumps(payload)

def parse_frontmatter_metadata(draft_path, filename):
    with open(draft_path, "r", encoding="utf-8") as f:
        raw_text = f.read().replace("\r\n", "\n")

    # 1. Isolate the top header section before main content/body
    header_lines = []
    body_lines = []
    lines = raw_text.splitlines()
    in_yaml = False
    yaml_opened = False

    for idx, line in enumerate(lines):
        stripped = line.strip()
        
        # Track frontmatter boundaries (---)
        if stripped == "---":
            if not yaml_opened:
                in_yaml = True
                yaml_opened = True
                continue
            else:
                in_yaml = False
                body_lines.extend(lines[idx + 1:])
                break

        # Stop header isolation at first H2 tag if no frontmatter delimiters exist
        if not in_yaml and stripped.startswith("##"):
            body_lines.extend(lines[idx:])
            break

        header_lines.append(line)

    header_text = "\n".join(header_lines)
    content_text = "\n".join(body_lines) if body_lines else raw_text

    # Default metadata dictionary
    meta = {
        "title": filename.replace("-", " ").title(),
        "platform": "CTF",
        "difficulty": "Medium",
        "category": "General",
        "tags": "",
        "status": "Active",
        "password": "",
        "proof": "",
        "description": ""
    }

    def sanitize_val(val):
        """Unpack Obsidian lists or single values into clean strings."""
        if isinstance(val, list):
            val = val[0] if len(val) > 0 else ""
        val = str(val or "").strip().strip("'\"")
        return val

    # 2. Attempt frontmatter parsing on the isolated top block
    parsed_meta = {}
    if yaml_opened:
        try:
            post = frontmatter.loads(raw_text)
            parsed_meta = {k.lower(): sanitize_val(v) for k, v in post.metadata.items()}
            content_text = post.content
        except Exception:
            parsed_meta = {}

    # 3. Fallback to key-value regex matching on the header section if frontmatter yielded nothing
    if not parsed_meta:
        kv_pattern = re.compile(
            r"^(Title|Platform|Difficulty|Category|Tags|Status|Password|Proof|Description)\s*[:=]\s*(.+)$",
            re.IGNORECASE | re.MULTILINE
        )
        for match in kv_pattern.finditer(header_text):
            k = match.group(1).lower()
            v = sanitize_val(match.group(2))
            parsed_meta[k] = v

    # Merge parsed values into metadata dict
    for k, v in parsed_meta.items():
        if k in meta and v:
            meta[k] = v

    # Standardize status casing
    meta["status"] = meta["status"].capitalize()
    raw_password = meta["password"]
    pass_hash = ""

    if meta["status"] == "Active":
        if len(raw_password) < 5:
            raise ValueError(
                f"[-] Security Rule Error in '{draft_path}': Active CTF writeups MUST have at least 5 characters. "
                f"Parsed Password: '{raw_password}' ({len(raw_password)} chars)."
            )
        pass_hash = hash_password(raw_password)
        print(f"🔒 [AES-256 Encrypted] Lock Enforced for '{filename}':")
        print(f"   ├─ Title             : {meta['title']}")
        print(f"   ├─ Cleartext Password : {raw_password}")
        print(f"   └─ SHA-256 Hash      : {pass_hash}")
    else:
        print(f"🔓 [Retired Lab] '{filename}' is set to Retired (No Lock Required).")

    meta["pass_hash"] = pass_hash
    meta["password"] = raw_password if meta["status"] == "Active" else ""
    meta["content"] = content_text

    return meta
    with open(draft_path, "r", encoding="utf-8") as f:
        raw_text = f.read().replace("\r\n", "\n")

    # Dictionary defaults
    meta = {
        "title": filename.replace("-", " ").title(),
        "platform": "CTF",
        "difficulty": "Medium",
        "category": "General",
        "tags": "",
        "status": "Active",
        "password": "",
        "proof": "",
        "description": ""
    }

    # Match lines formatted as Key = Value or Key: Value
    key_val_pattern = re.compile(r"^(Title|Platform|Difficulty|Category|Tags|Status|Password|Proof|Description)\s*[:=]\s*(.+)$", re.IGNORECASE | re.MULTILINE)
    
    for match in key_val_pattern.finditer(raw_text):
        key = match.group(1).lower()
        val = match.group(2).strip()
        meta[key] = val

    # Clean and derive parameters
    meta["title"] = meta["title"].strip()
    meta["status"] = meta["status"].strip().capitalize()
    
    raw_password = meta["password"].strip()
    pass_hash = ""
    
    if meta["status"] == "Active":
        if len(raw_password) < 5:
            raise ValueError(
                f"[-] Security Rule Error in '{draft_path}': Active CTF writeups MUST have at least 5 characters. "
                f"Parsed Password: '{raw_password}' ({len(raw_password)} chars)."
            )
        pass_hash = hash_password(raw_password)
        print(f"🔒 [AES-256 Encrypted] Lock Enforced for '{filename}':")
        print(f"   ├─ Title             : {meta['title']}")
        print(f"   ├─ Cleartext Password : {raw_password}")
        print(f"   └─ SHA-256 Hash      : {pass_hash}")
    else:
        print(f"🔓 [Retired Lab] '{filename}' is set to Retired (No Lock Required).")

    meta["pass_hash"] = pass_hash
    meta["password"] = raw_password if meta["status"] == "Active" else ""
    meta["content"] = raw_text

    return meta
    with open(draft_path, "r", encoding="utf-8") as f:
        raw_text = f.read().replace("\r\n", "\n")

    post = frontmatter.loads(raw_text)
    
    title = str(post.get("Title", filename.replace("-", " ").title())).strip()
    
    # Extract 'Status' strictly while handling both YAML strings and Obsidian lists
    raw_status = post.get("Status")
    if isinstance(raw_status, list) and len(raw_status) > 0:
        status_str = str(raw_status[0]).strip()
    elif isinstance(raw_status, str):
        status_str = raw_status.strip()
    else:
        status_str = "Active"

    status = status_str.capitalize()
    
    raw_password = str(post.get("Password") or "").strip()
    
    # Helper for handling other potential Obsidian YAML lists (Platform, Category, Difficulty)
    def extract_single_val(key, default):
        val = post.get(key, default)
        if isinstance(val, list) and len(val) > 0:
            return str(val[0]).strip()
        return str(val).strip() if val else default

    platform = extract_single_val("Platform", "CTF")
    difficulty = extract_single_val("Difficulty", "Medium")
    category = extract_single_val("Category", "General")
    description = str(post.get("Description", "")).strip()
    
    tags_list = post.get("Tags", [])
    if isinstance(tags_list, list):
        tags = ",".join(str(t) for t in tags_list)
    else:
        tags = str(tags_list).strip()

    pass_hash = ""
    if status == "Active":
        if len(raw_password) < 5:
            raise ValueError(
                f"[-] Security Rule Error in '{draft_path}': Active CTF writeups MUST have at least 5 characters. "
                f"Parsed Password: '{raw_password}' ({len(raw_password)} chars)."
            )
        pass_hash = hash_password(raw_password)
        print(f"🔒 [AES-256 Encrypted] Lock Enforced for '{filename}':")
        print(f"   ├─ Cleartext Password : {raw_password}")
        print(f"   └─ SHA-256 Hash      : {pass_hash}")
    else:
        print(f"🔓 [Retired Lab] '{filename}' is set to Retired (No Lock Required).")

    return {
        "title": title,
        "status": status,
        "password": raw_password if status == "Active" else "",
        "pass_hash": pass_hash,
        "platform": platform,
        "difficulty": difficulty,
        "category": category,
        "description": description,
        "tags": tags,
        "content": post.content
    }

def inline_local_images(html_content: str, draft_path: str) -> str:
    """Reads the raw Markdown draft for image tags, ensures they exist in HTML, and embeds them as Base64."""
    raw_md = Path(draft_path).read_text(encoding="utf-8")
    md_images = re.findall(r'!\[([^\]]*)\]\(([^)]+)\)', raw_md)
    print(f"[*] Found {len(md_images)} image(s) in {Path(draft_path).name}: {[p for _, p in md_images]}")

    for alt_text, img_path in md_images:
        img_name = Path(img_path).name
        if img_name not in html_content:
            print(f"[+] Injecting image into HTML: {img_name}")
            figure_html = (
                f'\n<figure class="my-6">\n'
                f'  <img src="{img_path}" alt="{alt_text}" class="rounded-lg border border-slate-700/80 w-full shadow-md" />\n'
                f'  <figcaption class="text-xs text-center text-slate-400 mt-2 font-mono">{alt_text}</figcaption>\n'
                f'</figure>\n'
            )
            if html_content.endswith("</div>"):
                html_content = html_content[:-6] + figure_html + "</div>"
            else:
                html_content += figure_html

    def replace_with_base64(match):
        full_tag = match.group(0)
        src_path = match.group(1)

        if src_path.startswith(("http://", "https://", "data:")):
            return full_tag

        local_file = DRAFT_IMAGES / Path(src_path).name
        if not local_file.is_file():
            print(f"[!] Warning: Image not found at {local_file}, leaving tag as-is.")
            return full_tag

        mime_type, _ = mimetypes.guess_type(local_file)
        mime_type = mime_type or "image/png"
        b64_data = base64.b64encode(local_file.read_bytes()).decode("utf-8")
        print(f"[+] Embedded {local_file.name} as Base64 ({len(b64_data) // 1024} KB)")

        return full_tag.replace(src_path, f"data:{mime_type};base64,{b64_data}")

    return re.sub(r'<img[^>]+src=["\']([^"\']+)["\'][^>]*>', replace_with_base64, html_content)
    
def clean_gemini_output(raw_text):
    cleaned = re.sub(r"^```html\s*", "", raw_text, flags=re.MULTILINE)
    cleaned = re.sub(r"^```\s*$", "", cleaned, flags=re.MULTILINE)
    return cleaned.strip()

def resolve_target_files():
    if args.file:
        target_path = Path(args.file)
        if not target_path.exists() and (DRAFTS_DIR / target_path.name).exists():
            target_path = DRAFTS_DIR / target_path.name
        if not target_path.exists():
            print(f"[!] Error: Specified file '{args.file}' does not exist.")
            sys.exit(1)
        return [str(target_path)]
    return glob.glob(str(DRAFTS_DIR / "*.md"))

def process_drafts():
    if DRY_RUN:
        print("[DRY-RUN MODE ACTIVE] No API calls or encryption will occur.\n")

    if not DRY_RUN:
        WRITEUPS_DIR.mkdir(parents=True, exist_ok=True)

    draft_files = resolve_target_files()
    if not draft_files:
        print("[!] No markdown draft files found.")
        return

    for draft_path in draft_files:
        filename = Path(draft_path).stem
        output_path = WRITEUPS_DIR / f"{filename}.html"
        
        print(f"\nProcessing draft: {Path(draft_path).name} ...")
        meta = parse_frontmatter_metadata(draft_path, filename)
        
        if DRY_RUN:
            print(f"[DRY-RUN] Target output: {output_path}\n")
            continue

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"Raw Notes:\n{meta['content']}",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.2,
            ),
        )
        
        raw_html_body = clean_gemini_output(response.text)

        # Overwrite whatever H1 title Gemini generates with the exact Title metadata
        raw_html_body = re.sub(
            r'<h1[^>]*>.*?</h1>',
            f'<h1 class="text-4xl sm:text-5xl font-bold text-slate-100 tracking-tight mb-4">{meta["title"]}</h1>',
            raw_html_body,
            count=1,
            flags=re.DOTALL
        )

        # Inline local screenshots as Base64 Data URIs BEFORE encryption
        raw_html_body = inline_local_images(raw_html_body, draft_path)

        if meta["status"] == "Active":
            # Encrypt HTML body using AES-256
            ciphertext_json = encrypt_html_content(raw_html_body, meta["password"])
            full_html = LOCKED_HTML_TEMPLATE.format(
                title=meta["title"],
                status=meta["status"],
                pass_hash=meta["pass_hash"],
                platform=meta["platform"],
                difficulty=meta["difficulty"],
                category=meta["category"],
                description=meta["description"],
                tags=meta["tags"],
                ciphertext_json=ciphertext_json
            )
        else:
            # Render cleartext HTML body for retired writeups
            full_html = UNLOCKED_HTML_TEMPLATE.format(
                title=meta["title"],
                status=meta["status"],
                pass_hash=meta["pass_hash"],
                platform=meta["platform"],
                difficulty=meta["difficulty"],
                category=meta["category"],
                description=meta["description"],
                tags=meta["tags"],
                content=raw_html_body
            )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_html)

        status_tag = "🔒 [AES-256 Encrypted]" if meta["status"] == "Active" else "🔓 [Cleartext Unlocked]"
        print(f"[✔] Successfully generated {output_path} {status_tag}")

if __name__ == "__main__":
    process_drafts()