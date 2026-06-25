FROM node:20-alpine
WORKDIR /app
COPY . .
ENV PORT=8080
ENV DATA_DIR=/app/data
ENV PUBLIC_DIR=/app
EXPOSE 8080
CMD ["node", "server.js"]
