FROM golang:1.23-alpine

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libpcap-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /app/server ./cmd/detector

EXPOSE 8081

CMD [ "/app/server"]