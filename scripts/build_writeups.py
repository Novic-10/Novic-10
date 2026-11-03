import os
import glob
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables from .env file locally
load_dotenv()

# Fetch API key from environment
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("GEMINI_API_KEY environment variable is not set!")

genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-1.5-flash")

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
You are an expert Cybersecurity Technical Writer. Take these raw CTF notes and format them into an executive-ready Writeup in clean HTML using Tailwind CSS classes. Use slate-900 containers, cyan accents, and font-mono for logs, hashes, and terminal commands.
Structure:
1. Executive Summary & Challenge Overview
2. Key Takeaways & Security Insights
3. Step-by-Step Investigation & Tooling
4. Question & Answer Solutions Table
Return ONLY the HTML inner content.
"""

def process_drafts():
    os.makedirs("writeups", exist_ok=True)
    draft_files = glob.glob("drafts/*.md")
    
    for draft_path in draft_files:
        filename = os.path.basename(draft_path).replace(".md", "")
        output_path = f"writeups/{filename}.html"
        
        with open(draft_path, "r", encoding="utf-8") as f:
            raw_notes = f.read()
            
        print(f"Processing {filename}...")
        response = model.generate_content(f"{SYSTEM_PROMPT}\n\nRaw Notes:\n{raw_notes}")
        
        full_html = HTML_TEMPLATE.format(
            title=filename.replace("-", " ").title(),
            content=response.text
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_html)

if __name__ == "__main__":
    process_drafts()
