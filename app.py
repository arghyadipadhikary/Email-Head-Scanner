from flask import Flask, render_template, request
import email
from email.policy import default
from analyzer import HeuristicNLPAnalyzer

app = Flask(__name__)

def parse_raw_email(raw_text):
    """
    Takes raw .eml text and extracts headers, plain text, and HTML.
    Hardened against malformed character set evasion techniques.
    """
    # Parse the raw text into an email object
    msg = email.message_from_string(raw_text, policy=default)
    
    # 1. Extract Headers
    headers = {}
    for key, value in msg.items():
        headers[key] = value
        
    # 2. Extract Body (Text and HTML)
    text_body = ""
    html_body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Skip attachments safely
            if "attachment" in content_disposition:
                continue
                
            try:
                # Hardened fallback to safeguard decoding cycles
                charset = part.get_content_charset() or 'utf-8'
                raw_payload = part.get_payload(decode=True)
                if raw_payload:
                    payload = raw_payload.decode(charset, errors='replace')
                    
                    if content_type == "text/plain":
                        text_body += payload
                    elif content_type == "text/html":
                        html_body += payload
            except Exception:
                continue
    else:
        # Not multipart, just a standard text or html email
        try:
            charset = msg.get_content_charset() or 'utf-8'
            raw_payload = msg.get_payload(decode=True)
            if raw_payload:
                payload = raw_payload.decode(charset, errors='replace')
                
                if msg.get_content_type() == "text/html":
                    html_body = payload
                else:
                    text_body = payload
        except Exception:
            pass

    # If there is no plain text but there is HTML, use HTML as the text body for lexical scanning
    if not text_body and html_body:
        text_body = html_body

    return headers, text_body, html_body


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        raw_email = request.form.get('raw_email', '')
        
        if not raw_email.strip():
            return render_template('index.html', raw_email="")

        # 1. Parse the incoming raw payload safely
        headers, text_body, html_body = parse_raw_email(raw_email)
        
        # 2. Spin up the engine and analyze
        engine = HeuristicNLPAnalyzer()
        results = engine.process_email(headers, text_body, html_body)
        
        # 3. Return the interface with calculated metrics
        return render_template('index.html', raw_email=raw_email, results=results)

    # If it's a GET request, just load the empty terminal workspace
    return render_template('index.html', raw_email="")

if __name__ == '__main__':
    # Running local debugging cycle smoothly
    app.run(debug=True)