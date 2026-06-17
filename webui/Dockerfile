FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go index.html ./
RUN CGO_ENABLED=0 go build -trimpath -o /webui .

FROM gcr.io/distroless/static-debian12
COPY --from=build /webui /webui
ENTRYPOINT ["/webui"]
