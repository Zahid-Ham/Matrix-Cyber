# How to Generate a GitHub Personal Access Token (Classic)

The Matrix Security Agent needs a **Classic** Personal Access Token (PAT) with `repo` permissions to automatically create branches and pull requests for remediation.

## why "Classic" (`ghp_`)?
While GitHub has new "Fine-grained" tokens (`github_pat_`), the **Classic** token (`ghp_`) is currently the most reliable way to grant the broad `repo` scope required for the agent to work on your private repositories without needing to configure permissions for every single repository individually.

## Step-by-Step Instructions

1.  **Log in to GitHub** and go to **Settings** (click your profile picture in the top right > Settings).
2.  Scroll down to the bottom of the left sidebar and click **Developer settings**.
3.  In the left sidebar, click **Personal access tokens** -> **Tokens (classic)**.
    *   *Note: Do NOT select "Fine-grained tokens".*
4.  Click the **Generate new token** button and select **Generate new token (classic)**.
5.  **Configure the Token:**
    *   **Note:** Give it a name like "Matrix Security Agent".
    *   **Expiration:** Set to "No expiration" or a duration you prefer (e.g., 90 days).
    *   **Select Scopes (CRITICAL):** check the box for **`repo`** (Full control of private repositories).
        *   This automatically selects `repo:status`, `repo_deployment`, `public_repo`, etc.
6.  Scroll to the bottom and click **Generate token**.
7.  **Copy the Token:**
    *   You will see a token starting with `ghp_`.
    *   **Copy this immediately**, as you won't be able to see it again.

## Update Your Environment

1.  Open your `backend/.env` file.
2.  Find the line `GITHUB_TOKEN=...`.
3.  Replace the value with your new `ghp_` token.
    ```env
    GITHUB_TOKEN=ghp_YourNewGeneratedTokenHere...
    ```
4.  **Restart the Backend:**
    *   Stop the running server (Ctrl+C).
    *   Run `uvicorn main:app --host 127.0.0.1 --port 8000 --reload` again.
