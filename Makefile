LINTERS_VERSION=v1.25.1

install:
	go get -u github.com/kyoh86/richgo

install-linters:
	go get -u golang.org/x/lint/golint
	GO111MODULE=on go get github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINTERS_VERSION)

lint:
	@golangci-lint run ./... && golint -set_exit_status ./...

clean:
	rm -f coverage.html covprofile.out

test:
	@go test -v ckks/negacyclic ckks -count=1 | sed ''/PASS/s//$$(printf "\033[32mPASS\033[0m")/'' | sed ''/FAIL/s//$$(printf "\033[31mFAIL\033[0m")/''

coverage:
	@go test -count=1 ./... -coverprofile=covprofile.out
	@go tool cover -html=covprofile.out -o coverage.html && rm covprofile.out

example-square:
	@go test -v examples/square_test.go

example-depth2:
	@go test -v -run Depth2 examples/depth_test.go

example-depth3:
	@go test -v -run Depth3 examples/depth_test.go

example-encoding:
	@go test -v examples/encoding_roundtrip_test.go

benchmark:
	@go test -run XXX ./... -v -bench=.
