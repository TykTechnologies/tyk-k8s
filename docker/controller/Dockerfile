# Start from the latest golang base image
FROM golang:latest as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o tyk-k8s .


######## Start a new stage from scratch #######
FROM alpine:latest

RUN apk --no-cache add ca-certificates

RUN mkdir -p /opt/tyk-k8s
WORKDIR /opt/tyk-k8s

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/tyk-k8s /opt/tyk-k8s/tyk-k8s

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./tyk-k8s", "start"]