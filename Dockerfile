FROM python:3.13-slim

WORKDIR /app

# Встановлення залежностей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копіювання коду додатку
COPY . .

# Встановлення змінних оточення
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Відкриття портів
EXPOSE 5000

# Запуск додатку
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]
