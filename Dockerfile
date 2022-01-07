FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.17.2-alpine3.14 as build

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0

WORKDIR /src
COPY . .

RUN apk add git
RUN VERSION=$(git describe --all --exact-match `git rev-parse HEAD` | grep tags | sed 's/tags\///') \
    && GIT_COMMIT=$(git rev-list -1 HEAD) \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=${CGO_ENABLED} go build \
        --ldflags "-s -w \
        -X github.com/jsiebens/brink/internal/version.GitCommit=${GIT_COMMIT}\
        -X github.com/jsiebens/brink/internal/version.Version=${VERSION}" \
        -a -installsuffix cgo -o brink cmd/brink/main.go

FROM --platform=${TARGETPLATFORM:-linux/amd64} alpine:3.14.2 as ship

RUN apk --no-cache add ca-certificates
RUN addgroup -S brink && adduser -S -g brink brink

COPY --from=build /src/brink /usr/local/bin

USER brink
ENTRYPOINT ["brink"]