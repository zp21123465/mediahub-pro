FROM python:3.11-alpine

LABEL org.opencontainers.image.source="https://github.com/zp21123465/mediahub-pro"
LABEL org.opencontainers.image.description="All-in-one automated private cinema hub"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

RUN apk add --no-cache tzdata gcc musl-dev libffi-dev
ENV TZ=Asia/Shanghai

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

COPY . .

EXPOSE 18888

VOLUME ["/app/data"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "18888"]
