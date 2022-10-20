FROM python:3.10.5-buster

WORKDIR /app

ADD . /app

RUN pip install -r requirements.txt

CMD python app.py
