FROM alpine:3.15.4

RUN apk --no-cache add ca-certificates
RUN addgroup -S brink && adduser -S -g brink brink

COPY brink /usr/local/bin/brink

USER brink
ENTRYPOINT ["brink"]
