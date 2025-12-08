# Publishing `react-native-libsignal-client`

This document describes how releases are cut and published to npm for this package.

- Package: `react-native-libsignal-client`
- Registry: https://registry.npmjs.org
- Default branch: `master`
- Publish mechanism: **GitHub Actions** (tag-based, from `master` only)

## 1. One–time setup

### 1.1 npm automation token

1. Log into https://www.npmjs.com/.
2. Go to **Profile → Access Tokens**.
3. Click **Generate New Token** and choose **Automation**.
4. Copy the token value.

### 1.2 GitHub secret: `NPM_TOKEN`

1. In the repo, go to  
   **Settings → Secrets and variables → Actions → New repository secret**.
2. Name: `NPM_TOKEN`
3. Value: the automation token.

### 1.3 GitHub workflow

Publishing is handled by `.github/workflows/publish.yml`.

- Triggers on tags `v*`
- Ensures the tag commit is on `master`
- Run lint
- Publishes to npm using `NODE_AUTH_TOKEN=${{ secrets.NPM_TOKEN }}`

## 2. Versioning

Use:

```
npm version patch
npm version minor
npm version major
```

This updates package.json, creates a commit, and creates a tag `v<version>`.

## 3. Release flow

```
git checkout master
git pull origin master

npm version patch   # or minor/major
git push origin master --follow-tags
```

GitHub Actions will automatically publish.

## 4. What CI does

1. Checks out repo
2. Fetches master and verifies tag is on master
3. Installs deps (`npm ci`)
4. Runs lint
5. Publishes with:

```
npm publish --access public
```

## 5. Troubleshooting

- **Tag not on master** → Create the tag on master.
- **Version exists** → Bump again and push.
- **403 error** → `NPM_TOKEN` lacks permission.

## 6. Security

- Never commit `NPM_TOKEN`
- Store only as GitHub secret or local env var
- Revoke and rotate on suspicion of leak

## 7. Summary

- Releases triggered by pushing tags `v*` on master
- Use `npm version` for bumping
- GitHub Actions handles lint and publishing
