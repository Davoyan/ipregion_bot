# 🌍 IPRegion Bot

A simple Telegram bot that detects the geographic region of any given IP address.

Try it out here: [@ipregion_bot](https://t.me/ipregion_bot).

## 🧩 Output example

![image](https://i.imgur.com/50ys6ga.png)

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Davoyan/ipregion_bot.git
```
2. Create the .env file from the sample and add your tokens:

```bash
cd ipregion_bot && cp .env.sample .env && nano .env
```

3. Build the Docker image and start the container:

```bash
docker compose build && docker compose up -d && docker compose logs -f
```

