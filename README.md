# DJY Hub Key Server

Express server for generating, managing, and verifying user-bound DJY keys. Key records are stored in `keys.json` beside the server.

## Run

```sh
npm install
ADMIN_PW='replace-with-a-strong-password' npm start
```

The server listens on port `3000` by default. Set `PORT` to use a different port.

Open `/admin?pw=YOUR_ADMIN_PASSWORD` to manage keys. Send `POST /verify` JSON with `key` and `userId` to claim or verify a key; `username` is optional.

The default admin password is `CHANGE_ME_NOW`. Set `ADMIN_PW` before exposing the server to a network. The current admin interface passes its password in the URL, so use it only over a trusted HTTPS deployment.