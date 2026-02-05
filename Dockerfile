FROM python:3.13-slim

WORKDIR /app

# Встановлення залежностей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Копіювання коду додатку
COPY . .

# Створення папки для БД
RUN mkdir -p /app/data

# Встановлення змінних оточення
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Відкриття портів
EXPOSE 5000

# Запуск додатку з Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "app:app"]
