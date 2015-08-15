FROM golang
RUN go get github.com/lib/pq
RUN go get github.com/gorilla/mux
RUN go get github.com/gorilla/sessions
ADD . /go/src/github.com/rentaroomsg/risa
RUN go install github.com/rentaroomsg/risa
ENTRYPOINT /go/bin/risa
EXPOSE 8080
