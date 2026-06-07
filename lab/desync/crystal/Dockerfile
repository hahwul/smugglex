FROM crystallang/crystal:1.20-alpine AS build
WORKDIR /app
COPY desync_lab.cr .
RUN crystal build --release desync_lab.cr -o desync_lab

FROM alpine:3.20
RUN apk add --no-cache gc pcre2 libevent
COPY --from=build /app/desync_lab /usr/local/bin/desync_lab
# Bind the proxy on all interfaces so it is reachable from outside the container.
ENV BIND_HOST=0.0.0.0
EXPOSE 9000
CMD ["desync_lab"]
