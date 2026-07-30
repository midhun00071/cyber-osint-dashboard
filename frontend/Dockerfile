FROM node:24-alpine AS dependencies

WORKDIR /app

COPY package*.json ./

RUN npm install

FROM node:24-alpine AS builder

WORKDIR /app

ARG APP_ENV=local
ARG NEXT_PUBLIC_API_BASE_URL
ENV APP_ENV=${APP_ENV} \
    NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL}

COPY --from=dependencies /app/node_modules ./node_modules
COPY . .

RUN npm run build

FROM node:24-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules

USER appuser

EXPOSE 3000

CMD ["npm", "start"]
