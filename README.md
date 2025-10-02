# IPRegion Bot
Telegram-бот для определения географического региона по IP-адресу.  
Попробовать можно здесь: [@ipregion_bot](https://t.me/ipregion_bot).

## Пример работы

![image](https://i.imgur.com/neYbeN6.png)

## Установка

1. Клонируем репозиторий:
```bash
git clone https://github.com/Davoyan/ipregion_bot.git
cd ipregion_bot
```
2. Заполняем свои токены в .env:

```bash
nano .env
```

3. Собираем Docker-образ и запускаем контейнер:

```bash
docker compose build && docker compose up -d && docker compose logs -f
```

