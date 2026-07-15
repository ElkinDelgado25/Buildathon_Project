# CyberSec Agent Web Console

This is a dependency-free static frontend. It calls the FastAPI backend over HTTP;
it never contains the OpenAI API key.

## Local design workflow

Keep the API running with Docker, then serve this directory from the project root:

```bash
python -m http.server 5173 --directory frontend
```

Open `http://localhost:5173`, enter `http://localhost:8000` in **API endpoint**,
then select **Connect API**. The URL is stored only in the current browser.

## Deployment

`render.yaml` deploys this directory as the `cybersecurity-agent-console` static
site alongside the API. After Render creates both services, enter the public API
URL in the page's **API endpoint** field. Do not put `OPENAI_API_KEY` in this
frontend or in browser JavaScript.
