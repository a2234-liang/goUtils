package utils

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"slices"
)

/*
<script>

	if ('EventSource' in window) {
	    let token = document.querySelector("#token").value
	    var eventsoure = new EventSource(`http://127.0.0.1:8080/sse/${token}`,{ withCredentials: true })
	    eventsoure.onmessage = function(event){
	        console.log("message=", event.data)
	    }
	}else{
	    document.write("No support eventsource")
	}

</script>
*/
var SseClients = make(map[string]chan string, 0)

type SseHander struct {
}

// sse处理函数
func (c *SseHander) Handler(ctx *gin.Context) {
	var (
		token = ctx.Param("token")
		w     = ctx.Writer
	)
	if _, ok := SseClients[token]; !ok {
		SseClients[token] = make(chan string)
	}
	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")
	ctx.Header("Access-Control-Allow-Origin", "*")
	if _, ok := w.(http.Flusher); !ok {
		slog.Error("server not support") //浏览器不兼容
		return
	}
	go func() {
		<-w.CloseNotify()
		slog.Info("client closed")
		delete(SseClients, token)
		return
	}()
	for {
		txt := <-SseClients[token]
		slog.Info("msg send to client", "token", token, "msg", txt)
		if _, err := fmt.Fprintf(w, "data:%v\n\n", txt); err != nil {
			return
		}
		w.Flush()
	}
}

// 广播文本
func (c *SseHander) BoardcaseText(msg string, tokens ...string) error {
	for token := range SseClients {
		if len(tokens) != 0 {
			if slices.Index(tokens, token) != -1 {
				SseClients[token] <- msg
			} else {
				continue
			}
		} else {
			SseClients[token] <- msg
		}
	}
	return nil
}

// 广播hashmap
func (c *SseHander) BoardcaseMap(data map[string]interface{}, tokens ...string) error {
	b, _ := json.Marshal(data)
	return c.BoardcaseText(string(b), tokens...)
}
