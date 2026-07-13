module github.com/Risen24x7/scantrace/scantrace-agent

go 1.25

require (
	github.com/Risen24x7/scantrace v0.0.0
	github.com/google/uuid v1.6.0
	github.com/joho/godotenv v1.5.1
	github.com/mattn/go-sqlite3 v1.14.22
	github.com/slack-go/slack v0.27.0
)

require github.com/gorilla/websocket v1.5.3 // indirect

replace github.com/Risen24x7/scantrace => ../
