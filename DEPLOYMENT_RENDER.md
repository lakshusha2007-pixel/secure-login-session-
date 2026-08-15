# 🚀 Deploying to Render.com (Step-by-Step Guide)

This guide walks you through hosting your **Secure Login & Session Management** PHP application on **Render.com** with free SSL, automatic CI/CD deployments, and cloud database connectivity.

---

## 📋 Prerequisites
1. Your repository is already pushed to GitHub:
   👉 `https://github.com/lakshusha2007-pixel/secure-login-session-.git`
2. A free account on [Render.com](https://render.com).
3. A free Cloud MySQL database (e.g. from [Aiven.io](https://aiven.io), [Clever Cloud](https://www.clever-cloud.com), or [Railway.app](https://railway.app)).

---

## Step 1: Push the `Dockerfile` to GitHub

Run the following commands in your terminal to push the new `Dockerfile` to GitHub:

```bash
git add Dockerfile
git commit -m "Add Dockerfile for Render deployment"
git push origin main
```

---

## Step 2: Get a Free Cloud MySQL Database

Render natively specializes in Web Services and PostgreSQL. For MySQL:

1. Create a free MySQL database on **[Aiven.io](https://aiven.io)** (Free Tier) or **[Clever-Cloud.com](https://www.clever-cloud.com)**.
2. Note down your database credentials:
   - `Host` (e.g., `mysql-xxxx.aivencloud.com`)
   - `Port` (e.g., `12345` or `3306`)
   - `User` (e.g., `avnadmin` or `root`)
   - `Password`
   - `Database Name` (e.g., `defaultdb` or `secure_login`)
3. Import your schema: Run/Import [`database_migration_v4.sql`](database_migration_v4.sql) into your database using phpMyAdmin, DBeaver, or MySQL Workbench.

---

## Step 3: Create a Web Service on Render.com

1. Log in to [Render Dashboard](https://dashboard.render.com/).
2. Click the **"New +"** button in the top right ➔ Select **"Web Service"**.
3. Under *Connect a repository*, choose **Build and deploy from a Git repository** ➔ Select your repository:
   `lakshusha2007-pixel/secure-login-session-`
4. Configure your Web Service:
   - **Name**: `secure-auth-app` (or your preferred name)
   - **Region**: Choose closest to you (e.g., *Singapore*, *Frankfurt*, or *Oregon*)
   - **Branch**: `main`
   - **Runtime**: **`Docker`** *(Render will automatically detect your `Dockerfile`)*
   - **Instance Type**: **`Free`**

---

## Step 4: Add Environment Variables in Render

Scroll down to the **Environment Variables** section on Render and click **Add Environment Variable** for each:

| Variable Name | Example Value / Description |
|---|---|
| `APP_ENV` | `production` |
| `APP_DEBUG` | `false` |
| `APP_KEY` | *(Generate a 64-char hex key e.g. from `.env`)* |
| `APP_URL` | `https://your-service-name.onrender.com` |
| `DB_HOST` | *Your Cloud MySQL Host* |
| `DB_PORT` | `3306` *(or your cloud database port)* |
| `DB_USER` | *Your Cloud MySQL User* |
| `DB_PASS` | *Your Cloud MySQL Password* |
| `DB_NAME` | *Your Cloud MySQL Database Name* |
| `MAIL_HOST` | `smtp.gmail.com` |
| `MAIL_PORT` | `587` |
| `MAIL_USERNAME` | `yourgmail@gmail.com` |
| `MAIL_PASSWORD` | *Your 16-character Google App Password* |
| `GOOGLE_CLIENT_ID` | *Your Google OAuth Client ID* |
| `GOOGLE_CLIENT_SECRET` | *Your Google OAuth Client Secret* |
| `GOOGLE_REDIRECT_URI` | `https://your-service-name.onrender.com/oauth_callback.php` |

---

## Step 5: Deploy & Verify

1. Click **"Create Web Service"** at the bottom of the page.
2. Render will pull your repository, build the Docker container with PHP 8.2 & Apache, and deploy it.
3. Once the build finishes (usually 1-2 minutes), you will see:
   `==> Your service is live at https://your-service-name.onrender.com`
4. Open the URL to access your live application!
