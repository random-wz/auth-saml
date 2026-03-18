# 构建阶段
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o saml-auth .

# 运行阶段
FROM alpine:3.18

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/saml-auth .
COPY config.example.yaml config.yaml

# 证书目录
RUN mkdir -p /app/certs

EXPOSE 8080

# 环境变量（可覆盖 config.yaml）
ENV SERVER_BASE_URL=http://localhost:8080
ENV CONFIG_FILE=/app/config.yaml

VOLUME ["/app/certs", "/app/config.yaml"]

ENTRYPOINT ["./saml-auth"]
