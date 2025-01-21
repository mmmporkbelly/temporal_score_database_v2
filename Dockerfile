FROM python:3.12.6
WORKDIR /
COPY . /
RUN pip install -r requirements.txt
CMD ["python3", "./main.py"]