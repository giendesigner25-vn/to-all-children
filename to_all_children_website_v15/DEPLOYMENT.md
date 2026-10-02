# TO ALL CHILDREN — V15 deployment

This build is prepared as a public web app. It runs with Node.js and SQLite and includes a health endpoint at `/health`.

## Option A — Render
1. Create a GitHub repository and upload this project.
2. In Render, create a new Web Service from the repository.
3. Choose **Docker**. The included `Dockerfile` is used automatically.
4. The included `render.yaml` configures the service and a persistent disk for `/app/data`.
5. Deploy. Render gives you a public `*.onrender.com` address.
6. For a custom domain, add your domain in the service's Custom Domains settings and follow the DNS records Render provides.

## Option B — Any Docker host
Build and run:

```bash
docker build -t to-all-children .
docker run -d --name to-all-children -p 3000:3000 -v to-all-children-data:/app/data to-all-children
```

Then put a domain/reverse proxy in front of port 3000.

## Local test

```bash
npm install
npm start
```
Open `http://localhost:3000`.

## Important
- The SQLite database lives in `data/stories.db`.
- On a cloud platform, persistent storage is required if you want users/stories to survive redeploys.
- The current parent sessions are in-memory, so a production multi-instance authentication system should later move sessions to a persistent store.
