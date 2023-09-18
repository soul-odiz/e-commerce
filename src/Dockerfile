FROM python:3.10-slim

WORKDIR /src

COPY . .

RUN pip install Flask
RUN pip install -r requirements.txt

EXPOSE 5000

CMD python app.py
