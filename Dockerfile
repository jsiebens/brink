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
        -X github.com/jsiebens/proxiro/internal/version.GitCommit=${GIT_COMMIT}\
        -X github.com/jsiebens/proxiro/internal/version.Version=${VERSION}" \
        -a -installsuffix cgo -o proxiro cmd/proxiro/main.go

FROM --platform=${TARGETPLATFORM:-linux/amd64} alpine:3.14.2 as ship

RUN apk --no-cache add ca-certificates
RUN addgroup -S proxiro && adduser -S -g proxiro proxiro

COPY --from=build /src/proxiro /usr/local/bin

USER proxiro
ENTRYPOINT ["proxiro"]