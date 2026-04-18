Provides Services Like :-
1) HTTP on PORT=5000
2) FTP on PORT=2121
3) SSH on PORT=2222

Version:- 3.0

How to Setup :-

1) create a virtual environment
2) install dependencies
3) run both python files on different terminal
4) (optional) tunnel through cloudflared

Step by step Commands :-

python3 -m venv venv
source /venv/bin/activate
pip install -r requirements.txt
python3 app.py
python3 dashboard_app.py
(optional) cloudflared --url http://127.0.0.1:5000
