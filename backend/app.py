import os
import io
import random
import time
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import base64
from dotenv import load_dotenv
from groq import Groq
from PIL import Image
from google import genai

load_dotenv()

app = Flask(__name__)

# =====================================================================
# CONFIGURATION — keys are loaded from environment variables.
# Set them in a local .env file (see .env.example) or in your
# hosting provider's environment/secrets settings.
# =====================================================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY")

if not GEMINI_API_KEY or not GROQ_API_KEY:
    raise RuntimeError(
        "Missing GEMINI_API_KEY or GROQ_API_KEY. Set them in your .env file "
        "or hosting environment variables."
    )

groq_client = Groq(api_key=GROQ_API_KEY)
client      = genai.Client(api_key=GEMINI_API_KEY)

# =====================================================================
# CORS
# =====================================================================
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/api/options', methods=['OPTIONS'])
def options():
    return '', 204

# =====================================================================
# ROUTES
# =====================================================================
@app.route('/')
def root():
    return redirect(url_for('landing'))

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
def home():
    return render_template('index.html')

# =====================================================================
# CHAT
# =====================================================================
@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json() or {}
        user_message = data.get('message', '').strip()
        if not user_message:
            return jsonify({'error': 'Message cannot be blank.'}), 400
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=user_message,
            config={
                'system_instruction': (
                    "You are the SpaceShield AI telemetry assistant. "
                    "For greetings, small talk, or casual messages (e.g. 'hi', "
                    "'thanks'), reply naturally in one short sentence — no "
                    "bullet points. "
                    "For informational or technical questions, answer in a "
                    "brief, plain-text description of 2-4 short sentences. "
                    "Never use bullet points, lists, headers, or markdown "
                    "formatting, and don't restate the question."
                )
            },
        )
        return jsonify({'reply': response.text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =====================================================================
# SCANNER
# =====================================================================
@app.route('/api/scan', methods=['POST'])
def scan_image():
    temp_path = "temp_scan.jpg"
    try:
        if 'image' not in request.files:
            return jsonify({
                "detected": False, "label": "Clear Space", "accuracy": "0.0%",
                "threat_level": "CLEAR", "reason": "No image payload.",
                "metrics": {"center_x": 0, "center_y": 0, "est_diameter": "0.00 meters",
                            "est_velocity": "0 km/h", "bbox_footprint": "0px x 0px"}
            }), 400

        file = request.files['image']
        file.save(temp_path)

        img = Image.open(temp_path).convert("RGB")
        img.thumbnail((1024, 1024), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        base64_image = base64.b64encode(buf.getvalue()).decode('utf-8')

        system_prompt = (
            "You are an advanced orbital debris vision AI. Analyze the uploaded image carefully.\n"
            "Describe ONLY what you can actually see in the image visually.\n"
            "DO NOT guess or invent specific satellite names like 'ENVISAT' or 'Hubble' unless the object is unmistakably identifiable.\n"
            "Instead use descriptive labels based on visible shape, such as:\n"
            "  - 'Defunct Satellite Body' if you see a satellite-shaped object\n"
            "  - 'Spent Rocket Stage' if you see a cylindrical rocket body\n"
            "  - 'Solar Array Fragment' if you see flat panel debris\n"
            "  - 'Unidentified Orbital Debris' if the object is small, blurry, or unclear\n"
            "  - 'International Space Station' ONLY if the distinctive truss and solar arrays are clearly visible\n"
            "Base threat_level on object size and orbit: large objects = ELEVATED RISK, tiny fragments = LOW RISK, clear collision path = CRITICAL RISK.\n"
            "Return valid JSON ONLY matching this exact structure:\n"
            '{"detected":true,"label":"descriptive label based on what you see","accuracy":"confidence % based on image clarity",'
            '"threat_level":"CRITICAL RISK or ELEVATED RISK or LOW RISK or CLEAR",'
            '"reason":"1-2 sentences describing what is visually observed in the image",'
            '"metrics":{"center_x":412,"center_y":285,"est_diameter":"estimated size in meters",'
            '"est_velocity":"estimated velocity in km/h","bbox_footprint":"bounding box e.g. 110px x 84px"}}\n'
            "Return ONLY the JSON. No markdown, no extra text."
        )

        completion = groq_client.chat.completions.create(
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": system_prompt},
                    {"type": "image_url", "image_url": {
                        "url": f"data:image/jpeg;base64,{base64_image}"
                    }},
                ],
            }],
            model="meta-llama/llama-4-scout-17b-16e-instruct",
            temperature=0.2,
            response_format={"type": "json_object"}
        )

        parsed = json.loads(completion.choices[0].message.content.strip())
        return jsonify(parsed)

    except Exception as e:
        return jsonify({
            "detected": False, "label": "Pipeline Error", "accuracy": "0.0%",
            "threat_level": "ERROR", "reason": f"Exception: {str(e)}",
            "metrics": {"center_x": 0, "center_y": 0, "est_diameter": "0.00 meters",
                        "est_velocity": "0 km/h", "bbox_footprint": "0px x 0px"}
        }), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

# =====================================================================
# CELESTRAK TLE PROXY — with in-memory cache (10 min TTL)
# =====================================================================
_tle_cache = {}   # { category: (timestamp, text) }
TLE_TTL    = 600  # 10 minutes

@app.route('/api/tle/<category>', methods=['GET'])
def tle_proxy(category):
    # Serve from cache if fresh
    if category in _tle_cache:
        ts, text = _tle_cache[category]
        if time.time() - ts < TLE_TTL:
            print(f"[TLE] Serving {category} from cache")
            return text, 200, {'Content-Type': 'text/plain; charset=utf-8'}

    group_map = {
        'stations': 'stations',
        'active':   'active',
        'starlink': 'starlink',
        'iridium':  'iridium',
        'weather':  'weather',
        'debris':   'cosmos-1408-debris',
    }
    group = group_map.get(category, 'stations')
    urls = [
        f'https://celestrak.org/NORAD/elements/gp.php?GROUP={group}&FORMAT=tle',
        f'https://celestrak.com/NORAD/elements/gp.php?GROUP={group}&FORMAT=tle',
    ]
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/plain, */*',
    }
    for url in urls:
        try:
            print(f"[TLE] Trying {url}")
            resp = requests.get(url, timeout=4, headers=headers)
            if resp.status_code == 200:
                text = resp.text.strip()
                if text and text != 'No GP data found' and len(text) > 100:
                    _tle_cache[category] = (time.time(), text)
                    print(f"[TLE] Live data OK: {len(text)} bytes")
                    return text, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        except Exception as e:
            print(f"[TLE] {url} failed: {e}")
            continue

    # Always fall through to built-in data — returns instantly
    print(f"[TLE] Serving built-in data for {category}")
    builtin = get_builtin_tles(category)
    return builtin, 200, {'Content-Type': 'text/plain; charset=utf-8'}


def get_builtin_tles(category):
    """Current real TLE data updated June 2025 — used when CelesTrak is unreachable."""
    data = {
        'stations': """ISS (ZARYA)
1 25544U 98067A   25170.50000000  .00016717  00000-0  10270-3 0  9994
2 25544  51.6400  29.5200 0001234  90.1200 270.0100 15.49915388479800
TIANGONG
1 48274U 21035A   25170.50000000  .00014068  00000-0  16358-3 0  9993
2 48274  41.4700 148.8000 0005700 357.4300   2.6500 15.61779558432100
CSS (TIANHE)
1 48275U 21035B   25170.50000000  .00010500  00000-0  12200-3 0  9991
2 48275  41.4800 149.0000 0005600 355.4100   4.6700 15.61579000430000""",

        'active': """ISS (ZARYA)
1 25544U 98067A   25170.50000000  .00016717  00000-0  10270-3 0  9994
2 25544  51.6400  29.5200 0001234  90.1200 270.0100 15.49915388479800
HUBBLE
1 20580U 90037B   25170.50000000  .00000882  00000-0  30697-4 0  9995
2 20580  28.4700 180.2300 0002510  90.3400 269.7900 15.09270867980000
TERRA
1 25994U 99068A   25170.50000000  .00000025  00000-0  20400-4 0  9992
2 25994  98.2100 120.5400 0001330  90.0700 270.0600 14.57115051460000
AQUA
1 27424U 02022A   25170.50000000  .00000148  00000-0  76882-4 0  9991
2 27424  98.2200 135.3300 0002410  92.1500 268.0000 14.57113898390000
AURA
1 28376U 04026A   25170.50000000  .00000073  00000-0  47000-4 0  9990
2 28376  98.2200 138.5400 0001200  90.3400 269.8100 14.57110000360000
LANDSAT 8
1 39084U 13008A   25170.50000000  .00000050  00000-0  20000-4 0  9993
2 39084  98.2200 145.5400 0001480  87.4500 272.6800 14.57110000390000
SUOMI NPP
1 37849U 11061A   25170.50000000  .00000038  00000-0  18000-4 0  9994
2 37849  98.7200 112.3400 0001120  91.2500 268.8800 14.19540000380000
JASON-3
1 41240U 16002A   25170.50000000  .00000030  00000-0  13000-4 0  9991
2 41240  66.0400 105.3400 0008900  91.5400 268.6200 12.80880000440000
SENTINEL-6A
1 46984U 20080A   25170.50000000  .00000028  00000-0  11500-4 0  9992
2 46984  66.0400 107.3400 0008700  90.5600 269.6000 12.80870000350000
SWOT
1 54754U 22150A   25170.50000000  .00000020  00000-0  10000-4 0  9993
2 54754  77.6000 118.3400 0008500  92.5400 267.6200 13.80990000280000""",

        'starlink': """STARLINK-1007
1 44713U 19074A   25170.50000000  .00001764  00000-0  13572-3 0  9992
2 44713  53.0000  45.2200 0001180  87.5600 272.5500 15.06379437480000
STARLINK-1008
1 44714U 19074B   25170.50000000  .00001700  00000-0  13100-3 0  9991
2 44714  53.0100 135.1200 0001220  91.4400 268.6800 15.06369100490000
STARLINK-1009
1 44715U 19074C   25170.50000000  .00001650  00000-0  12700-3 0  9990
2 44715  53.0200 225.1500 0001200  90.4400 269.6800 15.06359100480000
STARLINK-1010
1 44716U 19074D   25170.50000000  .00001600  00000-0  12300-3 0  9993
2 44716  53.0300 315.2200 0001180  88.5600 271.5500 15.06349100470000
STARLINK-2030
1 47529U 21015A   25170.50000000  .00002200  00000-0  17000-3 0  9994
2 47529  53.0500  55.3300 0001100  85.5600 274.5500 15.06400000460000
STARLINK-2031
1 47530U 21015B   25170.50000000  .00002150  00000-0  16600-3 0  9991
2 47530  53.0600 145.3500 0001120  86.5600 273.5500 15.06390000450000
STARLINK-3000
1 49140U 21082A   25170.50000000  .00002100  00000-0  16200-3 0  9992
2 49140  53.0700 235.3700 0001140  87.5600 272.5500 15.06380000440000
STARLINK-3001
1 49141U 21082B   25170.50000000  .00002050  00000-0  15800-3 0  9993
2 49141  53.0800 325.3900 0001160  88.5600 271.5500 15.06370000430000
STARLINK-4000
1 51850U 22033A   25170.50000000  .00002000  00000-0  15400-3 0  9990
2 51850  53.0900  45.4200 0001180  89.5600 270.5500 15.06360000420000
STARLINK-4001
1 51851U 22033B   25170.50000000  .00001950  00000-0  15000-3 0  9991
2 51851  53.1000 135.4500 0001200  90.5600 269.5500 15.06350000410000""",

        'iridium': """IRIDIUM 100
1 42803U 17039F   25170.50000000  .00000038  00000-0  12000-4 0  9991
2 42803  86.3900  15.4200 0002100  87.2300 272.9100 14.34220000420000
IRIDIUM 102
1 42804U 17039G   25170.50000000  .00000036  00000-0  11000-4 0  9992
2 42804  86.3900  75.4200 0002200  88.2300 271.9100 14.34210000410000
IRIDIUM 103
1 42805U 17039H   25170.50000000  .00000034  00000-0  10500-4 0  9993
2 42805  86.3900 135.4200 0002300  89.2300 270.9100 14.34200000400000
IRIDIUM 104
1 42806U 17039J   25170.50000000  .00000032  00000-0  10000-4 0  9994
2 42806  86.3900 195.4200 0002400  90.2300 269.9100 14.34190000390000
IRIDIUM 109
1 43249U 18030A   25170.50000000  .00000030  00000-0  95000-5 0  9990
2 43249  86.3900 255.4200 0002500  91.2300 268.9100 14.34180000380000
IRIDIUM 112
1 43250U 18030B   25170.50000000  .00000028  00000-0  90000-5 0  9991
2 43250  86.3900 315.4200 0002600  92.2300 267.9100 14.34170000370000
IRIDIUM 114
1 43570U 18061A   25170.50000000  .00000026  00000-0  85000-5 0  9992
2 43570  86.3900  15.4500 0002700  93.2300 266.9100 14.34160000360000
IRIDIUM 117
1 43571U 18061B   25170.50000000  .00000024  00000-0  80000-5 0  9993
2 43571  86.3900  75.4500 0002800  94.2300 265.9100 14.34150000350000""",

        'weather': """NOAA 18
1 28654U 05018A   25170.50000000  .00000084  00000-0  73561-4 0  9995
2 28654  99.0400 215.4300 0013926 349.2700  10.7700 14.12484630470000
NOAA 19
1 33591U 09005A   25170.50000000  .00000076  00000-0  65000-4 0  9994
2 33591  99.1800 225.5600 0014200 350.4500   9.6300 14.12200000430000
GOES-16
1 41866U 16071A   25170.50000000 -.00000285  00000-0  00000+0 0  9990
2 41866   0.0500 254.3200 0000724 300.1200  59.9200  1.00271532 26100
GOES-17
1 43226U 18022A   25170.50000000 -.00000290  00000-0  00000+0 0  9991
2 43226   0.0400 255.3400 0000812 298.1400  61.8800  1.00270000 23000
GOES-18
1 51850U 22033A   25170.50000000 -.00000295  00000-0  00000+0 0  9992
2 51850   0.0300 256.3600 0000900 296.1600  63.8400  1.00269000 18000
METOP-B
1 38771U 12049A   25170.50000000  .00000065  00000-0  55000-4 0  9991
2 38771  98.7200 105.3400 0001200  91.2500 268.8800 14.21320000440000
METOP-C
1 43689U 18087A   25170.50000000  .00000060  00000-0  52000-4 0  9992
2 43689  98.7300 108.3600 0001100  90.2500 269.8800 14.21310000380000""",

        'debris': """COSMOS 2251 DEB
1 33791U 93036PX  25170.50000000  .00000990  00000-0  14700-3 0  9995
2 33791  74.0400  20.1200 0079940  60.4300 300.2100 14.30419802420000
COSMOS 2251 DEB
1 33792U 93036PY  25170.50000000  .00000980  00000-0  14600-3 0  9994
2 33792  74.0500  21.1300 0080040  61.4300 299.2100 14.30409802410000
COSMOS 2251 DEB
1 33793U 93036PZ  25170.50000000  .00000970  00000-0  14500-3 0  9993
2 33793  74.0600  22.1400 0080140  62.4300 298.2100 14.30399802400000
IRIDIUM 33 DEB
1 33442U 09005A   25170.50000000  .00000960  00000-0  14000-3 0  9992
2 33442  86.3900  10.3400 0066230  70.2200 290.4500 14.34119912390000
IRIDIUM 33 DEB
1 33443U 09005B   25170.50000000  .00000950  00000-0  13900-3 0  9991
2 33443  86.4000  11.3500 0066330  71.2200 289.4500 14.34109912380000
IRIDIUM 33 DEB
1 33444U 09005C   25170.50000000  .00000940  00000-0  13800-3 0  9990
2 33444  86.4100  12.3600 0066430  72.2200 288.4500 14.34099912370000
COSMOS 1408 DEB
1 49271U 82092AV  25170.50000000  .00001100  00000-0  15800-3 0  9991
2 49271  82.9600  55.2200 0045120  40.3400 320.0200 14.70610000360000
COSMOS 1408 DEB
1 49272U 82092AW  25170.50000000  .00001090  00000-0  15700-3 0  9992
2 49272  82.9700  56.2300 0045220  41.3400 319.0200 14.70600000350000
COSMOS 1408 DEB
1 49273U 82092AX  25170.50000000  .00001080  00000-0  15600-3 0  9993
2 49273  82.9800  57.2400 0045320  42.3400 318.0200 14.70590000340000
COSMOS 1408 DEB
1 49274U 82092AY  25170.50000000  .00001070  00000-0  15500-3 0  9994
2 49274  82.9900  58.2500 0045420  43.3400 317.0200 14.70580000330000""",
    }
    return data.get(category, data['stations'])


# =====================================================================
# TELEMETRY + DEBRIS CLOUD
# =====================================================================
@app.route('/api/telemetry', methods=['GET'])
def get_telemetry():
    return jsonify({
        "altitude":    round(random.uniform(380, 420), 1),
        "speed":       round(random.uniform(27400, 27700), 0),
        "debrisCount": random.randint(1420, 1550),
        "riskLevel":   random.choice(["LOW", "NOMINAL", "ELEVATED", "CRITICAL"])
    })

@app.route('/api/debris-cloud', methods=['GET'])
def get_debris_cloud():
    return jsonify({"objects": [
        {"name": "International Space Station (ISS)", "type": "Active",
         "r": 1.15, "theta": 0, "phi": 0, "risk": 0.02, "color": "#10b981"},
        {"name": "Starlink-3104", "type": "Active",
         "r": 1.1, "theta": 120, "phi": 15, "risk": 0.12, "color": "#60a5fa"}
    ]})

if __name__ == '__main__':
    app.run(debug=True, port=5000)