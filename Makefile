build:
	./build.sh

format:
	gofmt -w -s $$(find . -type f -name '*.go' -not -path "./pkg/proto/*" -not -name "*.gen.go" -not -path "*/mock/*")
	goimports -w $$(find . -type f -name '*.go' -not -path "./pkg/proto/*" -not -name "*.gen.go" -not -path "*/mock/*")

