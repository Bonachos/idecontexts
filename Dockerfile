FROM golang:1.12-alpine
LABEL maintainer="jpmenezes@gmail.com" \
    description="This image contains a golang image for development purposes."

RUN mkdir -p /jpmenezes.com/idebo/contexts
WORKDIR /jpmenezes.com/idebo/contexts

EXPOSE 1333

RUN apk add --no-cache git mercurial gcc musl-dev

RUN go mod init jpmenezes.com/idebo/contexts

RUN go get -v github.com/rs/cors

COPY . .

CMD [ "go", "run", "jpmenezes.com/idebo/contexts" ]
