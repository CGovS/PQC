# Chooser (Chwazi-style finger picker, rigged)

Everyone puts a finger on the screen; after 2.5 s of holding still, one finger is picked
and its color floods the screen. One color can be given a hidden advantage.

## Run it locally

```sh
cd shwazy
python3 -m http.server 8000
```

- Same computer: open http://localhost:8000
- Phone/tablet (same Wi-Fi): open `http://<your-computer-ip>:8000`
  (find the IP with `ipconfig` on Windows or `ipconfig getifaddr en0` on macOS)
- Tip: "Add to Home Screen" makes it full-screen with no browser bar.

## Hidden settings

Triple-tap the **top-left corner** (with no other fingers down) to open settings:

| Setting | Default | Effect |
|---|---|---|
| Favored color | Green | The color with the advantage (`off` = fair) |
| Advantage | 4× | Favored finger's weight vs. 1 for everyone else; max = always wins |
| First finger gets favored color | On | Put your finger down first and you're always the favored color |

Win chance at weight `w` with `n` players is `w / (w + n − 1)`, e.g. 4× with 4 players = 57% (fair is 25%).
Settings are saved in the browser's localStorage.
