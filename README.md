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

1) python3 -m venv venv
2) source /venv/bin/activate
3) pip install -r requirements.txt
4) python3 app.py
5) python3 dashboard_app.py
6) (optional) cloudflared --url http://127.0.0.1:5000
