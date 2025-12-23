$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o tmp\authy.exe cmd\authy\main.go
