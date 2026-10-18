# Static web client on Cloud Run: build with Vite, serve with nginx.
# No Firebase config is baked in, so the app skips the sign-in gate and runs the
# chat directly. The agent URL is a build arg (Vite inlines it at build time).
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci 2>/dev/null || npm install
COPY . .
ARG VITE_AGENT_URL=https://shopping-agent-55485752139.us-central1.run.app/a2a/shopping_agent
RUN printf "VITE_AGENT_URL=%s\n" "$VITE_AGENT_URL" > .env.production && npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
