# 🛡️ Secure API Audit

![GitHub release](https://img.shields.io/github/v/release/felipewatter/secure-api-audit)
![GitHub](https://img.shields.io/github/license/felipewatter/secure-api-audit)
![GitHub language count](https://img.shields.io/github/languages/count/felipewatter/secure-api-audit)

A CLI tool to audit REST or GraphQL APIs for basic and advanced security practices.

---

## ✅ Features

- Checks security headers
- Detects open CORS configurations
- Verifies HTTPS usage
- Detects lack of authentication
- Supports aggressive (fuzz) mode
- CI-ready

---

## 💻 Usage

```bash
npx secure-api-audit --url=https://api.example.com --token=mytoken
```

---

## ⚙️ Options

- `--url` → API base URL (required)
- `--token` → Bearer token or API key
- `--aggressive` → Enable fuzz mode (optional)

---

## 💡 Best Practices

- Always audit before exposing endpoints
- Automate with CI pipelines
- Avoid wildcard CORS
- Always enforce HTTPS and security headers

---

## 🧑‍💻 Contributing

Pull requests and suggestions are welcome!

---

## 📄 License

MIT License