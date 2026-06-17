FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /ctmon .

FROM gcr.io/distroless/static-debian12
COPY --from=build /ctmon /ctmon
ENTRYPOINT ["/ctmon"]
