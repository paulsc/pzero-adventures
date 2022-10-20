import re
from flask import Flask, request
from flask_json import FlaskJSON, json_response

from util import verify, sign as _sign

KEY_ID = 'pzero-adventures'
FLAG = '**REDACTED**'

app = Flask(__name__)

json = FlaskJSON(app)
json.init_app(app)

highscores = []

@app.route("/")
def main():
    return open('index.html').read()

@app.route("/api/highscores")
def get_highscores():
    global highscores

    return json_response(200, data_=[{
        'name': h.get('name'),
        'score': h.get('score')
    } for h in highscores])


@app.route("/api/highscores", methods=["post"])
def post_highscore():
    global highscores

    data = request.get_json()

    try:
        name = data.get('name')
        score = data.get('score')
        signature = bytes.fromhex(data.get('signature', ''))
    except:
        return json_response(400, text="invalid parameters")

    if type(name) != str or len(name) != 3:
        return json_response(400, text="invalid name")
    if type(score) != int or not -2**16 <= score < 2**16:
        return json_response(400, text="invalid score")

    try:
        verify(KEY_ID, name, score, signature)
    except Exception as err:
        return json_response(400, text=err)

    player = {"name": name, "score": score}
    highscores.append(player)
    highscores = sorted(highscores, key=lambda row: row['score'], reverse=True)

    if len(highscores) > 10:
        highscores.pop(10)

    if score < 0:
        # FIX(mystiz): I heard that some players are so strong that the score is overflown.
        #              I'll send them the flag and hope the players are satisfied for now...
        return {"message": f"You performed so well so that you triggered an integer overflow! This is your flag: {FLAG}"}
    elif player in highscores:
        rank = highscores.index(player) + 1
        return {"message": f"Congratulations! You are currently at #{rank} on the scoreboard!"}
    else:
        return {"message": f"Better luck next time!"}


@app.route("/api/sign", methods=["post"])
def sign():
    data = request.get_json()

    name = data.get('name')
    score = data.get('score')

    if type(name) != str or len(name) != 3:
        return json_response(400, text="invalid name")
    if type(score) != int or score < 0:
        return json_response(400, text="invalid score")

    return {"signature": _sign(KEY_ID, name, score).hex()}


@app.route("/api/keys")
def get_key():
    with open(f'keys/{KEY_ID}.pub') as f:
        return {"key": f.read()}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=1337)
