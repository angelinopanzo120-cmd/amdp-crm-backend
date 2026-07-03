# AMDP backend — sem dependências externas (usa o SQLite embutido do Node 22)
FROM node:22-slim
WORKDIR /app
COPY . .
ENV NODE_ENV=production
# A porta é definida pela Railway via variável PORT; 3000 é só informativo.
EXPOSE 3000
CMD ["node", "server.js"]
