FROM golang:1.23.6-bookworm

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to leverage Docker's cache mechanism
COPY go.mod go.sum ./

# Download dependencies only if go.mod and go.sum have changed
RUN go mod download

# Copy the Go project files into the container
COPY . .

# Set the GOFLAGS environment variable to disable VCS stamping
ENV GOFLAGS=-buildvcs=false

# Build the Go project with c-shared mode to produce a shared object file
CMD ["go", "build", "-o", "/output/go-envoy-keyauth.so", "-buildmode=c-shared", "."]
