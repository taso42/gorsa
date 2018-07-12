GOPATH=$(shell pwd)
BINARY=gorsa

$(BINARY):
	go build -o $(BINARY) gorsa.go

clean:
	rm $(BINARY)

