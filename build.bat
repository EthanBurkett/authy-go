@echo off
set GOOS=windows
set GOARCH=amd64
go build -o tmp\authy.exe cmd\authy\main.go
