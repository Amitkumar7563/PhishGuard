from flask import Flask, request, jsonify
from flask_cors import CORS
#from detector import check_url
from detector import check_url, check_tld

app = Flask(__name__)
CORS(app)

from detector import check_url, check_tld, gemini_analysis
@app.route("/check", methods=["POST"])
def check():
    data = request.json

    url = data.get("url")

    result = check_url(url)


    #  Risk calculation
    risk = 0
    if not result["https"]:
        risk += 30
    if not result["domain"]:
        risk += 20
    if result["phishing"]:
        risk += 50
    if not check_tld(url):
        risk += 20
    
     
    #  Status determination
    if risk >= 70:
        status = "⚠️ PHISHING / MALICIOUS"
    elif risk >= 40:
        status = "⚠️ SUSPICIOUS"
    else:
        status = "✅ SAFE"
    try:
        gemini_report = gemini_analysis(url, result, risk)
    except Exception as e:
        gemini_report = "Gemini analysis failed."

    return jsonify({
        "status": status,
        "risk": risk,
        "checks": result,
        "gemini_report": gemini_report
    })


if __name__ == "__main__":
    app.run(debug=True)
